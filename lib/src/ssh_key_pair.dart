import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:convert/convert.dart';
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
        final pair = RsaKeyPair.decode(pem);
        return [pair.getPrivateKeys(passphrase)];
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
        final pair = RsaKeyPair.decode(pem);
        return pair.isEncrypted;
      default:
        throw UnsupportedError('Unsupported key type: ${pem.type}');
    }
  }

  /// [name] is the name of the algorithm used when saving the key. This only
  /// affects how the key is serialized.
  String get name;

  /// [type] indicates not only the encoding of the key, but also the the
  /// algorithm used when signing. Until now only RSA keys have [type]s that are
  /// different from [name].
  String get type;

  SSHHostKey toPublicKey();

  SSHSignature sign(Uint8List data);

  String toPem();
}

class OpenSSHKeyPairs {
  static const magic = 'openssh-key-v1';

  /// Name of the algorithm used to encrypt the private key. 'none' means no
  /// encryption.
  final String cipherName;

  /// Key derivation function used to derive the encryption key. 'none' means
  /// no key derivation thus no encryption.
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

  OpenSSHKeyPairs.unencrypted({
    required this.publicKeys,
    required this.privateKeyBlob,
  })  : cipherName = 'none',
        kdfName = 'none',
        kdfOptions = null;

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

    final keypairs = <SSHKeyPair>[];
    for (var i = 0; i < publicKeys.length; i++) {
      final type = reader.readUtf8();
      switch (type) {
        case 'ssh-rsa':
          keypairs.add(OpenSSHRsaKeyPair.readFrom(reader));
          break;
        case 'ssh-ed25519':
          keypairs.add(OpenSSHEd25519KeyPair.readFrom(reader));
          break;
        case 'ecdsa-sha2-nistp256':
        case 'ecdsa-sha2-nistp384':
        case 'ecdsa-sha2-nistp521':
          keypairs.add(OpenSSHEcdsaKeyPair.readFrom(reader));
          break;
        default:
          throw UnsupportedError('Unsupported key type: $type');
      }
    }

    return keypairs;
  }

  String toPem() {
    final writer = SSHMessageWriter();
    writer.writeBytes(Uint8List.fromList(magic.codeUnits));
    writer.writeUint8(0); // terminator of magic

    writer.writeUtf8(cipherName);
    writer.writeUtf8(kdfName);
    writer.writeString(kdfOptions?.encode() ?? Uint8List(0));

    writer.writeUint32(publicKeys.length);
    for (var i = 0; i < publicKeys.length; i++) {
      writer.writeString(publicKeys[i]);
    }

    writer.writeString(privateKeyBlob);
    return SSHPem('OPENSSH PRIVATE KEY', {}, writer.takeBytes()).encode(70);
  }

  Uint8List _decryptPrivateKeyBlob(Uint8List blob, Uint8List passphrase) {
    final cipher = SSHCipherType.fromName(cipherName);

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

  @override
  String toString() {
    return '$runtimeType{cipher: $cipherName, kdf: $kdfName, kdfOptions: $kdfOptions, keys.length: ${publicKeys.length}}';
  }
}

abstract class OpenSSHKdfOptions {
  Uint8List encode();
}

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
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeString(salt);
    writer.writeUint32(rounds);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return '$runtimeType{salt: ${latin1.decode(salt)}, rounds: $rounds}';
  }
}

abstract class OpenSSHKeyPair implements SSHKeyPair {
  void writeTo(SSHMessageWriter writer);

  @override
  String toPem() {
    final writer = SSHMessageWriter();
    final checkInt = Random().nextInt(0xFFFFFFFF);

    writer.writeUint32(checkInt);
    writer.writeUint32(checkInt);
    writer.writeUtf8(name);
    writeTo(writer);

    // pad with bytes 1, 2, 3, ...
    for (var i = 0; writer.length % 8 != 0; i++) {
      writer.writeUint8(i + 1);
    }

    return OpenSSHKeyPairs.unencrypted(
      publicKeys: [toPublicKey().encode()],
      privateKeyBlob: writer.takeBytes(),
    ).toPem();
  }
}

class OpenSSHRsaKeyPair with OpenSSHKeyPair {
  @override
  final name = 'ssh-rsa';

  @override
  final type = SSHRsaSignatureType.sha256;

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
    final signer = RSASigner(SHA256Digest(), '0609608648016503040201');

    signer.init(
      true,
      PrivateKeyParameter<RSAPrivateKey>(
        RSAPrivateKey(n, d, p, q),
      ),
    );

    return SSHRsaSignature(type, signer.generateSignature(data).bytes);
  }

  @override
  void writeTo(SSHMessageWriter writer) {
    writer.writeMpint(n);
    writer.writeMpint(e);
    writer.writeMpint(d);
    writer.writeMpint(iqmp);
    writer.writeMpint(p);
    writer.writeMpint(q);
    writer.writeUtf8(comment);
  }

  @override
  String toString() {
    return '$runtimeType(comment: "$comment")';
  }
}

class OpenSSHEd25519KeyPair with OpenSSHKeyPair {
  @override
  final name = 'ssh-ed25519';

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
    return SSHEd25519Signature(signer.sign(data).asTypedList.sublist(0, 64));
  }

  @override
  void writeTo(SSHMessageWriter writer) {
    writer.writeString(publicKey);
    writer.writeString(privateKey);
    writer.writeUtf8(comment);
  }

  @override
  String toString() {
    return '$runtimeType(comment: "$comment")';
  }
}

class OpenSSHEcdsaKeyPair with OpenSSHKeyPair {
  @override
  String get name => 'ecdsa-sha2-$curveId';

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
    return SSHEcdsaPublicKey(type: name, curveId: curveId, q: q);
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
  void writeTo(SSHMessageWriter writer) {
    writer.writeUtf8(curveId);
    writer.writeString(q);
    writer.writeMpint(d);
    writer.writeUtf8(comment);
  }

  @override
  String toString() {
    return '$runtimeType(comment: "$comment")';
  }
}

class RsaKeyPair {
  final RsaKeyPairDEKInfo? dekInfo;

  final Uint8List keyBlob;

  const RsaKeyPair(this.dekInfo, this.keyBlob);

  factory RsaKeyPair.decode(SSHPem pem) {
    final dekInfoHeader = pem.headers['DEK-Info'];

    final dekInfo =
        dekInfoHeader != null ? RsaKeyPairDEKInfo.parse(dekInfoHeader) : null;

    final keyBlob = pem.content;

    return RsaKeyPair(dekInfo, keyBlob);
  }

  bool get isEncrypted => dekInfo != null;

  RsaPrivateKey getPrivateKeys([String? passphrase]) {
    var keyBlob = this.keyBlob;

    if (isEncrypted) {
      if (passphrase == null) {
        throw ArgumentError('passphrase is required for encrypted key');
      }
      final passphraseBytes = Utf8Encoder().convert(passphrase);
      keyBlob = _decryptPrivateKeyBlob(passphraseBytes);
    }

    try {
      return RsaPrivateKey.decode(keyBlob);
    } catch (e) {
      throw SSHKeyDecodeError('Failed to decode private key', e);
    }
  }

  Uint8List _decryptPrivateKeyBlob(Uint8List passphrase) {
    final cipher = _getCipher(dekInfo!.algorithm);

    if (cipher == null) {
      throw UnsupportedError('Unsupported cipher: ${dekInfo!.algorithm}');
    }

    final kdfHash = _deriveKey(
      Uint8List.sublistView(dekInfo!.iv, 0, 8),
      passphrase,
      cipher.keySize,
    );

    final key = Uint8List.sublistView(kdfHash, 0, cipher.keySize);

    final decryptCipher =
        cipher.createCipher(key, dekInfo!.iv, forEncryption: false);

    return decryptCipher.processAll(keyBlob);
  }

  static SSHCipherType? _getCipher(String name) {
    switch (name.toUpperCase()) {
      case 'AES-128-CBC':
        return SSHCipherType.aes128cbc;
      case 'AES-192-CBC':
        return SSHCipherType.aes192cbc;
      case 'AES-256-CBC':
        return SSHCipherType.aes256cbc;
      case 'AES-128-CTR':
        return SSHCipherType.aes128ctr;
      case 'AES-192-CTR':
        return SSHCipherType.aes192ctr;
      case 'AES-256-CTR':
        return SSHCipherType.aes256ctr;
    }
    return null;
  }

  static Uint8List _deriveKey(Uint8List salt, Uint8List data, int length) {
    final result = BytesBuilder();
    var lastHash = Uint8List(0);

    while (result.length < length) {
      final digest = MD5Digest();
      final hash = Uint8List(digest.digestSize);
      digest.reset();
      digest.update(lastHash, 0, lastHash.length);
      digest.update(data, 0, data.length);
      digest.update(salt, 0, salt.length);
      digest.doFinal(hash, 0);
      result.add(hash);
      lastHash = hash;
    }

    return result.takeBytes();
  }
}

/// Corresponds to the `DEK-Info` header in PEM.
class RsaKeyPairDEKInfo {
  final String algorithm;
  final Uint8List iv;

  RsaKeyPairDEKInfo(this.algorithm, this.iv);

  factory RsaKeyPairDEKInfo.parse(String header) {
    final parts = header.split(',');
    if (parts.length != 2) {
      throw FormatException('Invalid DEK-Info header: $header');
    }
    return RsaKeyPairDEKInfo(
      parts[0],
      Uint8List.fromList(hex.decode(parts[1])),
    );
  }

  @override
  String toString() {
    return '$runtimeType(algorithm: $algorithm, iv: ${hex.encode(iv)})';
  }
}

class RsaPrivateKey implements SSHKeyPair {
  @override
  final name = 'ssh-rsa';

  @override
  final type = SSHRsaSignatureType.sha256;

  final BigInt version;
  final BigInt n;
  final BigInt e;
  final BigInt d;
  final BigInt p;
  final BigInt q;
  final BigInt exponent1;
  final BigInt exponent2;
  final BigInt coefficient;

  RsaPrivateKey(
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

  factory RsaPrivateKey.decode(Uint8List keyBlob) {
    final parser = ASN1Parser(keyBlob);

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

    return RsaPrivateKey(
      version,
      n,
      e,
      d,
      p,
      q,
      exponent1,
      exponent2,
      coefficient,
    );
  }

  @override
  SSHHostKey toPublicKey() {
    return SSHRsaPublicKey(e, n);
  }

  @override
  SSHRsaSignature sign(Uint8List data) {
    final signer = RSASigner(SHA256Digest(), '0609608648016503040201');

    signer.init(
      true,
      PrivateKeyParameter<RSAPrivateKey>(
        RSAPrivateKey(n, d, p, q),
      ),
    );

    return SSHRsaSignature(type, signer.generateSignature(data).bytes);
  }

  @override
  String toPem() {
    final sequence = ASN1Sequence();
    sequence.add(ASN1Integer(version));
    sequence.add(ASN1Integer(n));
    sequence.add(ASN1Integer(e));
    sequence.add(ASN1Integer(d));
    sequence.add(ASN1Integer(p));
    sequence.add(ASN1Integer(q));
    sequence.add(ASN1Integer(exponent1));
    sequence.add(ASN1Integer(exponent2));
    sequence.add(ASN1Integer(coefficient));
    return SSHPem('RSA PRIVATE KEY', {}, sequence.encodedBytes).encode(64);
  }

  @override
  String toString() {
    return '$runtimeType(version: $version)';
  }
}
