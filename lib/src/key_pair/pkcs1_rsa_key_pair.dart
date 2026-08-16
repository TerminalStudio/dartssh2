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

  @override
  String? get comment => null;

  @override
  bool get shouldProbe => false;

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
