import 'dart:convert';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:convert/convert.dart';
import 'package:dartssh2/src/algorithm/ssh_cipher_type.dart';
import 'package:dartssh2/src/hostkey/hostkey_rsa.dart';
import 'package:dartssh2/src/ssh_errors.dart';
import 'package:dartssh2/src/ssh_hostkey.dart';
import 'package:dartssh2/src/ssh_key_pair.dart';
import 'package:dartssh2/src/ssh_pem.dart';
import 'package:dartssh2/src/utils/cipher_ext.dart';
import 'package:pointycastle/export.dart';

/// Container for an RSA private key encoded in PKCS#1 format (`BEGIN RSA PRIVATE KEY`).
class RsaKeyPair {
  /// Header encryption metadata from PEM DEK-Info header, if encrypted.
  final RsaKeyPairDEKInfo? dekInfo;

  /// Raw bytes of the ASN.1 DER-encoded RSA private key blob.
  final Uint8List keyBlob;

  /// Creates an [RsaKeyPair] container with optional [dekInfo] and [keyBlob].
  const RsaKeyPair(this.dekInfo, this.keyBlob);

  /// Decodes an [RsaKeyPair] from a parsed [SSHPem] structure.
  factory RsaKeyPair.decode(SSHPem pem) {
    final dekInfoHeader = pem.headers['DEK-Info'];

    final dekInfo =
        dekInfoHeader != null ? RsaKeyPairDEKInfo.parse(dekInfoHeader) : null;

    final keyBlob = pem.content;

    return RsaKeyPair(dekInfo, keyBlob);
  }

  /// Whether the RSA private key is encrypted with a passphrase.
  bool get isEncrypted => dekInfo != null;

  /// Decrypts (if needed) and parses the [RsaPrivateKey].
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
    } on UnsupportedError {
      rethrow;
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

/// Represents the `DEK-Info` header in legacy PEM private keys (RFC 1421).
class RsaKeyPairDEKInfo {
  /// Encryption algorithm name (e.g. `AES-128-CBC`, `DES-EDE3-CBC`).
  final String algorithm;

  /// Initialization vector.
  final Uint8List iv;

  /// Creates a [RsaKeyPairDEKInfo] with [algorithm] and [iv].
  RsaKeyPairDEKInfo(this.algorithm, this.iv);

  /// Parses a PEM `DEK-Info` header string (e.g. `AES-128-CBC,F18D71E0B...`).
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

/// An RSA private key decoded from PKCS#1 ASN.1 DER format.
class RsaPrivateKey implements SSHKeyPair {
  @override
  final name = 'ssh-rsa';

  @override
  final type = SSHRsaSignatureType.sha256;

  @override
  String? get comment => null;

  @override
  bool get shouldProbe => false;

  /// ASN.1 syntax version number.
  final BigInt version;

  /// RSA modulus n.
  final BigInt n;

  /// RSA public exponent e.
  final BigInt e;

  /// RSA private exponent d.
  final BigInt d;

  /// Prime factor p.
  final BigInt p;

  /// Prime factor q.
  final BigInt q;

  /// Exponent 1 (d mod (p-1)).
  final BigInt exponent1;

  /// Exponent 2 (d mod (q-1)).
  final BigInt exponent2;

  /// CRT coefficient (inverse of q mod p).
  final BigInt coefficient;

  /// Creates an [RsaPrivateKey] with all RSA CRT components.
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

  /// Decodes an [RsaPrivateKey] from PKCS#1 ASN.1 DER [keyBlob].
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
