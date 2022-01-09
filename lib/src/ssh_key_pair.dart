import 'dart:convert';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/hostkey/hostkey_ecdsa.dart';
import 'package:dartssh2/src/hostkey/hostkey_ed25519.dart';
import 'package:dartssh2/src/hostkey/hostkey_rsa.dart';
import 'package:dartssh2/src/ssh_hostkey.dart';
import 'package:dartssh2/src/ssh_message.dart';
import 'package:dartssh2/src/utils/bcrypt.dart';
import 'package:dartssh2/src/utils/cipher_ext.dart';
import 'package:dartssh2/src/utils/list.dart';
import 'package:pinenacl/ed25519.dart' as ed25519;
import 'package:pointycastle/export.dart';

abstract class SSHKeyPair {
  static List<SSHKeyPair> fromPem(String pemText, [String? passphrase]) {
    final pem = SSHPem.decode(pemText);
    switch (pem.type) {
      case 'OPENSSH PRIVATE KEY':
        final pairs = OpenSSHKeyPairs.decode(pem.content);
        return pairs.getPrivateKeys(passphrase);
      case 'RSA PRIVATE KEY':
        return [RsaKeyPair.decode(pem.content)];
      default:
        throw UnsupportedError('Unsupported key type: ${pem.type}');
    }
  }

  static bool isEncryptedPem(String pemText) {
    final pem = SSHPem.decode(pemText);
    switch (pem.type) {
      case 'OPENSSH PRIVATE KEY':
        final pairs = OpenSSHKeyPairs.decode(pem.content);
        return pairs.isEncrypted;
      case 'RSA PRIVATE KEY':
        return false;
      default:
        throw UnsupportedError('Unsupported key type: ${pem.type}');
    }
  }

  String get type;

  SSHHostKey toPublicKey();

  SSHSignature sign(Uint8List data);
}

class OpenSSHKeyPairs {
  static const magic = 'openssh-key-v1';

  /// Name of the algorithm used to encrypt the private key.
  final String cipherName;

  /// Key derivation function used to derive the encryption key.
  final String kdfName;

  /// Options for the key derivation function.
  final OpenSSHKdfOptions? kdfOptions;

  /// List of public keys.
  final List<Uint8List> publicKeys;

  /// List of private keys.
  final Uint8List privateKeyBlob;

  /// Whether the private key is encrypted.
  bool get isEncrypted => cipherName != 'none';

  OpenSSHKeyPairs({
    required this.cipherName,
    required this.kdfName,
    required this.kdfOptions,
    required this.publicKeys,
    required this.privateKeyBlob,
  });

  factory OpenSSHKeyPairs.decode(Uint8List keyBlob) {
    final reader = SSHMessageReader(keyBlob);
    final actualMagic = reader.readBytes(magic.length);
    if (!actualMagic.equals(magic.codeUnits)) {
      throw FormatException('Invalid magic: ${latin1.decode(actualMagic)}');
    }
    reader.readUint8(); // terminator of magic
    final cipher = reader.readUtf8();
    final kdfName = reader.readUtf8();

    late final OpenSSHBcryptKdfOptions? kdfOptions;
    final kdfOptionsBlock = reader.readString();

    if (cipher == 'none') {
      kdfOptions = null;
    } else if (kdfName == 'bcrypt') {
      kdfOptions = OpenSSHBcryptKdfOptions.decode(kdfOptionsBlock);
    } else {
      throw UnsupportedError('Unsupported key derivation function: $kdfName');
    }

    final keyCount = reader.readUint32();
    final publicKeys = <Uint8List>[];
    for (var i = 0; i < keyCount; i++) {
      publicKeys.add(reader.readString());
    }

    final privateKeysBlob = reader.readString();

    return OpenSSHKeyPairs(
      cipherName: cipher,
      kdfName: kdfName,
      kdfOptions: kdfOptions,
      publicKeys: publicKeys,
      privateKeyBlob: privateKeysBlob,
    );
  }

  List<SSHKeyPair> getPrivateKeys([String? passphrase]) {
    late Uint8List unencryptedKeys;

    if (isEncrypted) {
      if (passphrase == null) {
        throw SSHKeyDecryptError('Private key is encrypted');
      }
      final passphraseBytes = Utf8Encoder().convert(passphrase);
      unencryptedKeys = _decryptPrivateKeyBlob(privateKeyBlob, passphraseBytes);
    } else {
      if (passphrase != null) {
        throw ArgumentError('Passphrase is not required for unencrypted keys');
      }
      unencryptedKeys = privateKeyBlob;
    }

    final reader = SSHMessageReader(unencryptedKeys);
    final checkInt1 = reader.readUint32();
    final checkInt2 = reader.readUint32();
    if (checkInt1 != checkInt2) {
      if (isEncrypted) {
        throw SSHKeyDecryptError('Invalid passphrase');
      } else {
        throw SSHKeyDecryptError('Invalid private key');
      }
    }

    final keys = <SSHKeyPair>[];
    for (var i = 0; i < publicKeys.length; i++) {
      final type = reader.readUtf8();
      switch (type) {
        case 'ssh-rsa':
          keys.add(OpenSSHRsaKeyPair.readFrom(reader));
          break;
        case 'ssh-ed25519':
          keys.add(OpenSSHEd25519KeyPair.readFrom(reader));
          break;
        case 'ecdsa-sha2-nistp256':
        case 'ecdsa-sha2-nistp384':
        case 'ecdsa-sha2-nistp521':
          keys.add(OpenSSHEcdsaKeyPair.readFrom(reader));
          break;
        default:
          throw UnsupportedError('Unsupported key type: $type');
      }
    }

    return keys;
  }

  Uint8List _decryptPrivateKeyBlob(Uint8List blob, Uint8List passphrase) {
    final cipher = _findCipher(cipherName);

    if (cipher == null) {
      throw UnsupportedError('Unsupported cipher: $cipherName');
    }

    if (this.kdfOptions is! OpenSSHBcryptKdfOptions) {
      throw UnsupportedError('Unsupported key derivation function: $kdfName');
    }

    final kdfOptions = this.kdfOptions as OpenSSHBcryptKdfOptions;

    final kdfHash = Uint8List(cipher.keySize + cipher.ivSize);

    bcrypt_pbkdf(
      passphrase,
      passphrase.lengthInBytes,
      kdfOptions.salt,
      kdfOptions.salt.lengthInBytes,
      kdfHash,
      kdfHash.lengthInBytes,
      kdfOptions.rounds,
    );

    final key = Uint8List.view(kdfHash.buffer, 0, cipher.keySize);
    final iv = Uint8List.view(kdfHash.buffer, cipher.keySize, cipher.ivSize);
    final decryptCipher = cipher.createCipher(key, iv, forEncryption: false);
    return decryptCipher.processAll(blob);
  }

  static SSHCipherType? _findCipher(String cipherName) {
    for (var cipher in SSHCipherType.values) {
      if (cipher.name == cipherName) {
        return cipher;
      }
    }
  }

  @override
  String toString() {
    return '$runtimeType{cipher: $cipherName, kdf: $kdfName, kdfOptions: $kdfOptions, keys.length: ${publicKeys.length}}';
  }
}

abstract class OpenSSHKdfOptions {}

class OpenSSHBcryptKdfOptions implements OpenSSHKdfOptions {
  final Uint8List salt;
  final int rounds;

  OpenSSHBcryptKdfOptions(this.salt, this.rounds);

  factory OpenSSHBcryptKdfOptions.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    final salt = reader.readString();
    final rounds = reader.readUint32();
    return OpenSSHBcryptKdfOptions(salt, rounds);
  }

  @override
  String toString() {
    return '$runtimeType{salt: ${latin1.decode(salt)}, rounds: $rounds}';
  }
}

class OpenSSHRsaKeyPair implements SSHKeyPair {
  @override
  final type = 'ssh-rsa';

  final BigInt n;
  final BigInt e;

  final BigInt d;
  final BigInt iqmp;
  final BigInt p;
  final BigInt q;

  final String comment;

  OpenSSHRsaKeyPair(
    this.n,
    this.e,
    this.d,
    this.iqmp,
    this.p,
    this.q,
    this.comment,
  );

  factory OpenSSHRsaKeyPair.readFrom(SSHMessageReader reader) {
    final n = reader.readMpint();
    final e = reader.readMpint();
    final d = reader.readMpint();
    final iqmp = reader.readMpint();
    final p = reader.readMpint();
    final q = reader.readMpint();
    final comment = reader.readUtf8();
    return OpenSSHRsaKeyPair(n, e, d, iqmp, p, q, comment);
  }

  @override
  SSHHostKey toPublicKey() {
    return SSHRsaPublicKey(e, n);
  }

  @override
  SSHRsaSignature sign(Uint8List data) {
    final signer = RSASigner(SHA1Digest(), '06052b0e03021a');

    signer.init(
      true,
      PrivateKeyParameter<RSAPrivateKey>(
        RSAPrivateKey(n, d, p, q),
      ),
    );

    return SSHRsaSignature(
      SSHRsaSignatureType.sha1,
      signer.generateSignature(data).bytes,
    );
  }

  @override
  String toString() {
    return '$runtimeType(comment: "$comment")';
  }
}

class OpenSSHEd25519KeyPair implements SSHKeyPair {
  @override
  final type = 'ssh-ed25519';

  final Uint8List publicKey;

  final Uint8List privateKey;

  final String comment;

  OpenSSHEd25519KeyPair(this.publicKey, this.privateKey, this.comment);

  factory OpenSSHEd25519KeyPair.readFrom(SSHMessageReader reader) {
    final publicKey = reader.readString();
    final privateKey = reader.readString();
    final comment = reader.readUtf8();
    return OpenSSHEd25519KeyPair(publicKey, privateKey, comment);
  }

  @override
  SSHHostKey toPublicKey() {
    return SSHEd25519PublicKey(publicKey);
  }

  @override
  SSHEd25519Signature sign(Uint8List data) {
    final signer = ed25519.SigningKey.fromValidBytes(privateKey);
    return SSHEd25519Signature(signer.sign(data).buffer.asUint8List(0, 64));
  }

  @override
  String toString() {
    return '$runtimeType(comment: "$comment")';
  }
}

class OpenSSHEcdsaKeyPair implements SSHKeyPair {
  @override
  String get type => 'ecdsa-sha2-$curveId';

  final String curveId;

  final Uint8List q;

  final BigInt d;

  final String comment;

  OpenSSHEcdsaKeyPair(this.curveId, this.q, this.d, this.comment);

  factory OpenSSHEcdsaKeyPair.readFrom(SSHMessageReader reader) {
    final curve = reader.readUtf8();
    final q = reader.readString();
    final d = reader.readMpint();
    final comment = reader.readUtf8();
    return OpenSSHEcdsaKeyPair(curve, q, d, comment);
  }

  @override
  SSHHostKey toPublicKey() {
    return SSHEcdsaPublicKey(type: type, curveId: curveId, q: q);
  }

  @override
  SSHEcdsaSignature sign(Uint8List data) {
    late Digest hash;
    late ECDomainParameters curve;

    switch (curveId) {
      case 'nistp256':
        hash = SHA256Digest();
        curve = ECCurve_secp256r1();
        break;
      case 'nistp384':
        hash = SHA384Digest();
        curve = ECCurve_secp384r1();
        break;
      case 'nistp521':
        hash = SHA512Digest();
        curve = ECCurve_secp521r1();
        break;
      default:
        throw UnsupportedError('Unsupported curve: $curveId');
    }

    final signer = ECDSASigner(hash);

    signer.init(
      true,
      ParametersWithRandom(
        PrivateKeyParameter(ECPrivateKey(d, curve)),
        FortunaRandom()..seed(KeyParameter(randomBytes(32))),
      ),
    );

    final signature = signer.generateSignature(data) as ECSignature;
    return SSHEcdsaSignature('ecdsa-sha2-$curveId', signature.r, signature.s);
  }

  @override
  String toString() {
    return '$runtimeType(comment: "$comment")';
  }
}

class RsaKeyPair implements SSHKeyPair {
  @override
  final type = 'ssh-rsa';

  final BigInt version;
  final BigInt n;
  final BigInt e;
  final BigInt d;
  final BigInt p;
  final BigInt q;
  final BigInt exponent1;
  final BigInt exponent2;
  final BigInt coefficient;

  RsaKeyPair(
    this.version,
    this.n,
    this.e,
    this.d,
    this.p,
    this.q,
    this.exponent1,
    this.exponent2,
    this.coefficient,
  );

  factory RsaKeyPair.decode(Uint8List data) {
    final parser = ASN1Parser(data);

    final sequence = parser.nextObject() as ASN1Sequence;
    final version = (sequence.elements[0] as ASN1Integer).valueAsBigInteger;
    final n = (sequence.elements[1] as ASN1Integer).valueAsBigInteger;
    final e = (sequence.elements[2] as ASN1Integer).valueAsBigInteger;
    final d = (sequence.elements[3] as ASN1Integer).valueAsBigInteger;
    final p = (sequence.elements[4] as ASN1Integer).valueAsBigInteger;
    final q = (sequence.elements[5] as ASN1Integer).valueAsBigInteger;
    final exponent1 = (sequence.elements[6] as ASN1Integer).valueAsBigInteger;
    final exponent2 = (sequence.elements[7] as ASN1Integer).valueAsBigInteger;
    final coefficient = (sequence.elements[8] as ASN1Integer).valueAsBigInteger;

    return RsaKeyPair(
      version!,
      n!,
      e!,
      d!,
      p!,
      q!,
      exponent1!,
      exponent2!,
      coefficient!,
    );
  }

  @override
  SSHHostKey toPublicKey() {
    return SSHRsaPublicKey(e, n);
  }

  @override
  SSHRsaSignature sign(Uint8List data) {
    final signer = RSASigner(SHA1Digest(), '06052b0e03021a');

    signer.init(
      true,
      PrivateKeyParameter<RSAPrivateKey>(
        RSAPrivateKey(n, d, p, q),
      ),
    );

    return SSHRsaSignature(
      SSHRsaSignatureType.sha1,
      signer.generateSignature(data).bytes,
    );
  }

  @override
  String toString() {
    return '$runtimeType(version: $version)';
  }
}
