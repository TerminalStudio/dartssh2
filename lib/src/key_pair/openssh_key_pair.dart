import 'dart:convert';
import 'dart:typed_data';

import 'package:dartssh2/src/algorithm/ssh_cipher_type.dart';
import 'package:dartssh2/src/hostkey/hostkey_ecdsa.dart';
import 'package:dartssh2/src/hostkey/hostkey_ed25519.dart';
import 'package:dartssh2/src/hostkey/hostkey_rsa.dart';
import 'package:dartssh2/src/ssh_errors.dart';
import 'package:dartssh2/src/ssh_hostkey.dart';
import 'package:dartssh2/src/ssh_key_pair.dart';
import 'package:dartssh2/src/ssh_message.dart';
import 'package:dartssh2/src/ssh_pem.dart';
import 'package:dartssh2/src/utils/bcrypt.dart';
import 'package:dartssh2/src/utils/cipher_ext.dart';
import 'package:dartssh2/src/utils/list.dart';
import 'package:pinenacl/ed25519.dart' as ed25519;
import 'package:pointycastle/export.dart';

/// Container for private keys encoded in OpenSSH format (`openssh-key-v1`).
class OpenSSHKeyPairs {
  /// Magic header identifier for OpenSSH private key files.
  static const magic = 'openssh-key-v1';

  /// Name of the algorithm used to encrypt the private key. 'none' means no
  /// encryption.
  final String cipherName;

  /// Key derivation function used to derive the encryption key. 'none' means
  /// no key derivation thus no encryption.
  final String kdfName;

  /// Options for the key derivation function.
  final OpenSSHKdfOptions? kdfOptions;

  /// List of public keys in SSH wire format.
  final List<Uint8List> publicKeys;

  /// Raw bytes of the private key section.
  final Uint8List privateKeyBlob;

  /// Whether the private key is encrypted.
  bool get isEncrypted => cipherName != 'none';

  /// Creates an [OpenSSHKeyPairs] container.
  OpenSSHKeyPairs({
    required this.cipherName,
    required this.kdfName,
    required this.kdfOptions,
    required this.publicKeys,
    required this.privateKeyBlob,
  });

  /// Creates an unencrypted [OpenSSHKeyPairs] container.
  OpenSSHKeyPairs.unencrypted({
    required this.publicKeys,
    required this.privateKeyBlob,
  })  : cipherName = 'none',
        kdfName = 'none',
        kdfOptions = null;

  /// Decodes OpenSSH private key binary [keyBlob].
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

  /// Decrypts and parses the private keys contained in this key file.
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

  /// Encodes this container to OpenSSH PEM format.
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

    try {
      final decryptCipher = cipher.createCipher(key, iv, forEncryption: false);
      return decryptCipher.processAll(blob);
    } catch (e) {
      throw SSHKeyDecryptError('Failed to decrypt private key', e);
    }
  }

  @override
  String toString() {
    return '$runtimeType{cipher: $cipherName, kdf: $kdfName, kdfOptions: $kdfOptions, keys.length: ${publicKeys.length}}';
  }
}

/// Abstract base class for OpenSSH key derivation function options.
abstract class OpenSSHKdfOptions {
  /// Encodes KDF options to binary format.
  Uint8List encode();
}

/// Bcrypt key derivation parameters used in OpenSSH private key format.
class OpenSSHBcryptKdfOptions implements OpenSSHKdfOptions {
  /// Salt bytes used in bcrypt PBKDF.
  final Uint8List salt;

  /// Iteration rounds for bcrypt PBKDF.
  final int rounds;

  /// Creates a new [OpenSSHBcryptKdfOptions] with [salt] and [rounds].
  OpenSSHBcryptKdfOptions(this.salt, this.rounds);

  /// Decodes [OpenSSHBcryptKdfOptions] from binary [data].
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

/// Mixin for OpenSSH format key pair implementations.
abstract mixin class OpenSSHKeyPair implements SSHKeyPair {
  @override
  String? get comment => null;

  @override
  bool get shouldProbe => false;

  /// Serializes private key components into [writer].
  void writeTo(SSHMessageWriter writer);

  @override
  String toPem() {
    final writer = SSHMessageWriter();
    final checkInt = ByteData.sublistView(randomBytes(4)).getUint32(0);

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

/// An RSA private/public key pair encoded in OpenSSH format.
class OpenSSHRsaKeyPair with OpenSSHKeyPair {
  @override
  final name = 'ssh-rsa';

  @override
  final type = SSHRsaSignatureType.sha256;

  /// Modulus.
  final BigInt n;

  /// Public exponent.
  final BigInt e;

  /// Private exponent.
  final BigInt d;

  /// Inverse of q modulo p.
  final BigInt iqmp;

  /// Prime factor p.
  final BigInt p;

  /// Prime factor q.
  final BigInt q;

  @override
  final String comment;

  /// Creates an [OpenSSHRsaKeyPair] with components and key [comment].
  OpenSSHRsaKeyPair(
    this.n,
    this.e,
    this.d,
    this.iqmp,
    this.p,
    this.q,
    this.comment,
  );

  /// Reads an [OpenSSHRsaKeyPair] from an OpenSSH binary [reader].
  factory OpenSSHRsaKeyPair.readFrom(SSHMessageReader reader) {
    final n = reader.readMpint();
    final e = reader.readMpint();
    final d = reader.readMpint();
    final iqmp = reader.readMpint();
    final p = reader.readMpint();
    final q = reader.readMpint();
    final comment = reader.readUtf8(allowMalformed: true);
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

/// An Ed25519 private/public key pair encoded in OpenSSH format.
class OpenSSHEd25519KeyPair with OpenSSHKeyPair {
  @override
  final name = 'ssh-ed25519';

  @override
  final type = 'ssh-ed25519';

  /// 32-byte Ed25519 public key.
  final Uint8List publicKey;

  /// 64-byte Ed25519 private key seed / expanded key.
  final Uint8List privateKey;

  @override
  final String comment;

  /// Creates an [OpenSSHEd25519KeyPair] with [publicKey], [privateKey], and [comment].
  OpenSSHEd25519KeyPair(this.publicKey, this.privateKey, this.comment);

  /// Reads an [OpenSSHEd25519KeyPair] from an OpenSSH binary [reader].
  factory OpenSSHEd25519KeyPair.readFrom(SSHMessageReader reader) {
    final publicKey = reader.readString();
    final privateKey = reader.readString();
    final comment = reader.readUtf8(allowMalformed: true);
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

/// An ECDSA (NIST P-256, P-384, P-521) private/public key pair encoded in OpenSSH format.
class OpenSSHEcdsaKeyPair with OpenSSHKeyPair {
  @override
  String get name => 'ecdsa-sha2-$curveId';

  @override
  String get type => 'ecdsa-sha2-$curveId';

  /// Curve identifier (e.g. `nistp256`, `nistp384`, `nistp521`).
  final String curveId;

  /// Uncompressed public point Q.
  final Uint8List q;

  /// Private scalar d.
  final BigInt d;

  @override
  final String comment;

  /// Creates an [OpenSSHEcdsaKeyPair] with [curveId], public point [q], private key [d], and [comment].
  OpenSSHEcdsaKeyPair(this.curveId, this.q, this.d, this.comment);

  /// Reads an [OpenSSHEcdsaKeyPair] from an OpenSSH binary [reader].
  factory OpenSSHEcdsaKeyPair.readFrom(SSHMessageReader reader) {
    final curve = reader.readUtf8();
    final q = reader.readString();
    final d = reader.readMpint();
    final comment = reader.readUtf8(allowMalformed: true);
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
