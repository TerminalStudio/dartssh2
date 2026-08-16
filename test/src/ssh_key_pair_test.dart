import 'dart:convert';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/hostkey/hostkey_ecdsa.dart';
import 'package:dartssh2/src/ssh_message.dart';
import 'package:test/test.dart';

import '../test_utils.dart';

void main() {
  final rsaPrivate = fixture('ssh-rsa/id_rsa');
  final rsaPrivateOpenSSH = fixture('ssh-rsa/id_rsa.openssh');

  final rsaPrivateEncrypted = fixture('ssh-rsa-passphrase/id_rsa');
  final rsaPassphrase = fixture('ssh-rsa-passphrase/passphrase');

  final ecdsaNistP256Private = fixture('ecdsa-sha2-nistp256/id_ecdsa');
  final ecdsaNistP384Private = fixture('ecdsa-sha2-nistp384/id_ecdsa');
  final ecdsaNistP521Private = fixture('ecdsa-sha2-nistp521/id_ecdsa');

  final ed25519Private = fixture('ssh-ed25519/id_ed25519');
  final ed25519PrivateEncrypted = fixture('ssh-ed25519-passphrase/id_ed25519');
  final ed25519PrivatePassphrase = fixture('ssh-ed25519-passphrase/passphrase');

  const legacyEcPrivateKey = '''-----BEGIN EC PRIVATE KEY-----
MIIBaAIBAQQg7TXJD04t4e/CrwIdaxF1FJ+PSF0kTzMQs5TOp9L0MvKggfowgfcC
AQEwLAYHKoZIzj0BAQIhAP////8AAAABAAAAAAAAAAAAAAAA////////////////
MFsEIP////8AAAABAAAAAAAAAAAAAAAA///////////////8BCBaxjXYqjqT57Pr
vVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMVAMSdNgiG5wSTamZ44ROdJreBn36QBEEE
axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54W
K84zV2sxXs7LtkBoN79R9QIhAP////8AAAAA//////////+85vqtpxeehPO5ysL8
YyVRAgEBoUQDQgAEQ3EUZAOS4yK43BKX5gl1BPUWPN3CsU0xrptfxnItUD34jPc0
ybMM3pZ6HeBa89ariwVsl/wCYzZfgR64JAC1nQ==
-----END EC PRIVATE KEY-----''';

  const legacyEcPublicKey =
      'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBENxFGQDkuMiuNwSl+YJdQT1FjzdwrFNMa6bX8ZyLVA9+Iz3NMmzDN6Weh3gWvPWq4sFbJf8AmM2X4EeuCQAtZ0= ecdsa 256-083024';

  final legacyEcPrivateKeyWithoutPublic = () {
    final pem = SSHPem.decode(legacyEcPrivateKey);
    final sequence = ASN1Parser(pem.content).nextObject() as ASN1Sequence;
    final stripped = ASN1Sequence();
    for (final element in sequence.elements) {
      if (element.tag != 0xA1) {
        stripped.add(element);
      }
    }
    return SSHPem('EC PRIVATE KEY', {}, stripped.encodedBytes).encode(64);
  }();

  final legacyEcPrivateKeyEncrypted = () {
    final lines = legacyEcPrivateKey.trim().split('\n');
    final body = lines.sublist(1, lines.length - 1).join('\n');
    return '''-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,74E0BC77BE064544

$body
-----END EC PRIVATE KEY-----''';
  }();

  const malformedEcPrivateKey = '''-----BEGIN EC PRIVATE KEY-----
MAA=
-----END EC PRIVATE KEY-----''';

  test('SSHKeyPair.fromPem works with RSA private key', () async {
    final pem = rsaPrivate;
    final keypair = SSHKeyPair.fromPem(pem);
    expect(keypair.length, 1);
    expect(keypair.single, isA<RsaPrivateKey>());
  });

  test('SSHKeyPair.fromPem works with ECdSA private key', () async {
    final pem = ecdsaNistP256Private;
    final keypair = SSHKeyPair.fromPem(pem);
    expect(keypair.length, 1);
    expect(keypair.single, isA<OpenSSHEcdsaKeyPair>());
  });

  test('SSHKeyPair.fromPem works with ECDSA nistp384 private key', () async {
    final pem = ecdsaNistP384Private;
    final keypairs = SSHKeyPair.fromPem(pem);

    expect(keypairs.length, 1);
    final keypair = keypairs.single as OpenSSHEcdsaKeyPair;
    expect(keypair.curveId, 'nistp384');
  });

  test('SSHKeyPair.fromPem works with ECDSA nistp521 private key', () async {
    final pem = ecdsaNistP521Private;
    final keypairs = SSHKeyPair.fromPem(pem);

    expect(keypairs.length, 1);
    final keypair = keypairs.single as OpenSSHEcdsaKeyPair;
    expect(keypair.curveId, 'nistp521');
  });

  test('SSHKeyPair.fromPem works with Ed25519 private key', () async {
    final pem = ed25519Private;
    final keypairs = SSHKeyPair.fromPem(pem);
    expect(keypairs.length, 1);
    expect(keypairs.single, isA<OpenSSHEd25519KeyPair>());
  });

  test('SSHKeyPair.fromPem works with legacy EC PRIVATE KEY format', () async {
    final keypairs = SSHKeyPair.fromPem(legacyEcPrivateKey);
    expect(keypairs.length, 1);
    final keypair = keypairs.single as OpenSSHEcdsaKeyPair;

    expect(keypair.curveId, 'nistp256');

    final publicBlob = base64.decode(legacyEcPublicKey.split(' ')[1]);
    final publicKey = SSHEcdsaPublicKey.decode(Uint8List.fromList(publicBlob));

    expect(keypair.q, publicKey.q);
  });

  test(
    'SSHKeyPair.fromPem works with legacy EC PRIVATE KEY without embedded public key',
    () async {
      final keypairs = SSHKeyPair.fromPem(legacyEcPrivateKeyWithoutPublic);
      expect(keypairs.length, 1);
      final keypair = keypairs.single as OpenSSHEcdsaKeyPair;

      final publicBlob = base64.decode(legacyEcPublicKey.split(' ')[1]);
      final publicKey =
          SSHEcdsaPublicKey.decode(Uint8List.fromList(publicBlob));

      expect(keypair.curveId, 'nistp256');
      expect(keypair.q, publicKey.q);
    },
  );

  test('SSHKeyPair.fromPem rejects passphrase for unencrypted EC PRIVATE KEY',
      () {
    expect(
      () => SSHKeyPair.fromPem(legacyEcPrivateKey, 'test'),
      throwsArgumentError,
    );
  });

  test('SSHKeyPair.isEncryptedPem detects encrypted EC PRIVATE KEY', () {
    expect(SSHKeyPair.isEncryptedPem(legacyEcPrivateKeyEncrypted), isTrue);
  });

  test('SSHKeyPair.fromPem rejects encrypted EC PRIVATE KEY for now', () {
    expect(
      () => SSHKeyPair.fromPem(legacyEcPrivateKeyEncrypted),
      throwsA(isA<UnsupportedError>()),
    );
  });

  test('SSHKeyPair.fromPem throws decode error on malformed EC PRIVATE KEY',
      () {
    expect(
      () => SSHKeyPair.fromPem(malformedEcPrivateKey),
      throwsA(isA<SSHKeyDecodeError>()),
    );
  });

  test('SSHKeyPair.isEncryptedPem works with RSA private key', () async {
    final pem = rsaPrivate;
    final pemEncrypted = rsaPrivateEncrypted;
    expect(SSHKeyPair.isEncryptedPem(pem), false);
    expect(SSHKeyPair.isEncryptedPem(pemEncrypted), true);
  });

  test('SSHKeyPair.isEncryptedPem works with ed25519 private key', () async {
    final pem = ed25519Private;
    final pemEncrypted = ed25519PrivateEncrypted;
    expect(SSHKeyPair.isEncryptedPem(pem), false);
    expect(SSHKeyPair.isEncryptedPem(pemEncrypted), true);
  });

  test('SSHKeyPair.fromPem can decrypt RSA private key', () async {
    final pem = rsaPrivateEncrypted;
    final passphrase = rsaPassphrase;
    final keypair = SSHKeyPair.fromPem(pem, passphrase);
    expect(keypair.length, 1);
    expect(keypair.single, isA<RsaPrivateKey>());
    expect(keypair.single.toPem(), rsaPrivate);
  });

  test('SSHKeyPair.fromPem can decrypt ed25519 private key', () async {
    final pem = ed25519PrivateEncrypted;
    final passphrase = ed25519PrivatePassphrase;
    final keypairs = SSHKeyPair.fromPem(pem, passphrase);
    expect(keypairs.length, 1);
    expect(keypairs.single, isA<OpenSSHEd25519KeyPair>());
  });

  test('SSHKeyPair.fromPem with wrong passphrase throws on RSA key', () async {
    final pem = rsaPrivateEncrypted;
    final passphrase = 'wrong';
    expect(
      () => SSHKeyPair.fromPem(pem, passphrase),
      throwsA(isA<SSHKeyDecodeError>()),
    );
  });

  test('SSHKeyPair.fromPem with wrong passphrase throws on ed25519', () async {
    final pem = ed25519PrivateEncrypted;
    final passphrase = 'wrong';
    expect(
      () => SSHKeyPair.fromPem(pem, passphrase),
      throwsA(isA<SSHKeyDecodeError>()),
    );
  });

  test('RsaPrivateKey.toPem() works', () async {
    final pem = rsaPrivate;
    final keypair = SSHKeyPair.fromPem(pem).single;
    expect(keypair.toPem(), pem);
  });

  test('OpenSSHRsaKeyPair.toPem() works', () async {
    final pem1 = rsaPrivateOpenSSH;
    final keypair1 = SSHKeyPair.fromPem(pem1).single as OpenSSHRsaKeyPair;

    final pem2 = keypair1.toPem();
    final keypair2 = SSHKeyPair.fromPem(pem2).single as OpenSSHRsaKeyPair;

    expect(pem1.length, pem2.length);

    final dataToSign = Uint8List.fromList('random-data-to-sign'.codeUnits);
    final signature1 = keypair1.sign(dataToSign);
    final signature2 = keypair2.sign(dataToSign);

    expect(signature1.type, signature2.type);
    expect(signature1.signature, signature2.signature);
  });

  test('OpenSSHEcdsaKeyPair.toPem() works', () async {
    final pem1 = ecdsaNistP256Private;
    final keypair1 = SSHKeyPair.fromPem(pem1).single as OpenSSHEcdsaKeyPair;

    final pem2 = keypair1.toPem();
    final keypair2 = SSHKeyPair.fromPem(pem2).single as OpenSSHEcdsaKeyPair;

    expect(pem1.length, pem2.length);

    expect(keypair1.curveId, keypair2.curveId);
    expect(keypair1.d, keypair2.d);
    expect(keypair1.q, keypair2.q);
  });

  test('OpenSSHEcdsaKeyPair.toPem() works for nistp384', () async {
    final pem1 = ecdsaNistP384Private;
    final keypair1 = SSHKeyPair.fromPem(pem1).single as OpenSSHEcdsaKeyPair;

    final pem2 = keypair1.toPem();
    final keypair2 = SSHKeyPair.fromPem(pem2).single as OpenSSHEcdsaKeyPair;

    expect(keypair1.curveId, keypair2.curveId);
    expect(keypair1.d, keypair2.d);
    expect(keypair1.q, keypair2.q);
  });

  test('OpenSSHEcdsaKeyPair.toPem() works for nistp521', () async {
    final pem1 = ecdsaNistP521Private;
    final keypair1 = SSHKeyPair.fromPem(pem1).single as OpenSSHEcdsaKeyPair;

    final pem2 = keypair1.toPem();
    final keypair2 = SSHKeyPair.fromPem(pem2).single as OpenSSHEcdsaKeyPair;

    expect(keypair1.curveId, keypair2.curveId);
    expect(keypair1.d, keypair2.d);
    expect(keypair1.q, keypair2.q);
  });

  test('OpenSSHEd25519KeyPair.toPem() works', () async {
    final pem1 = ed25519Private;
    final keypair1 = SSHKeyPair.fromPem(pem1).single as OpenSSHEd25519KeyPair;

    final pem2 = keypair1.toPem();
    final keypair2 = SSHKeyPair.fromPem(pem2).single as OpenSSHEd25519KeyPair;

    expect(pem1.length, pem2.length);

    final dataToSign = Uint8List.fromList('random-data-to-sign'.codeUnits);
    final signature1 = keypair1.sign(dataToSign);
    final signature2 = keypair2.sign(dataToSign);

    expect(signature1.signature, signature2.signature);
  });

  group('SSHKeyPair edge cases and error handling', () {
    test('SSHKeyPair.fromPem throws UnsupportedError for unknown PEM type', () {
      const unsupportedPem = '''-----BEGIN CERTIFICATE-----
MIIB
-----END CERTIFICATE-----''';
      expect(
        () => SSHKeyPair.fromPem(unsupportedPem),
        throwsA(isA<UnsupportedError>()),
      );
    });

    test('SSHKeyPair.isEncryptedPem throws UnsupportedError for unknown PEM type', () {
      const unsupportedPem = '''-----BEGIN CERTIFICATE-----
MIIB
-----END CERTIFICATE-----''';
      expect(
        () => SSHKeyPair.isEncryptedPem(unsupportedPem),
        throwsA(isA<UnsupportedError>()),
      );
    });

    test('SSHKeyPair.isEncryptedPem returns false for unencrypted RSA/EC/OpenSSH', () {
      expect(SSHKeyPair.isEncryptedPem(rsaPrivate), isFalse);
      expect(SSHKeyPair.isEncryptedPem(ed25519Private), isFalse);
      expect(SSHKeyPair.isEncryptedPem(legacyEcPrivateKey), isFalse);
    });

    test('OpenSSHKeyPairs.decode throws on invalid magic', () {
      final invalid = Uint8List.fromList('wrong-magic-long-enough\x00'.codeUnits);
      expect(
        () => OpenSSHKeyPairs.decode(invalid),
        throwsA(isA<FormatException>()),
      );
    });

    test('OpenSSHKeyPairs.decode throws on unsupported KDF', () {
      final writer = SSHMessageWriter();
      writer.writeBytes(Uint8List.fromList(OpenSSHKeyPairs.magic.codeUnits));
      writer.writeUint8(0);
      writer.writeUtf8('aes256-ctr');
      writer.writeUtf8('scrypt'); // unsupported KDF
      writer.writeString(Uint8List(0));
      writer.writeUint32(0);
      writer.writeString(Uint8List(0));

      expect(
        () => OpenSSHKeyPairs.decode(writer.takeBytes()),
        throwsA(isA<UnsupportedError>()),
      );
    });

    test('OpenSSHKeyPairs.getPrivateKeys throws when passphrase missing on encrypted key', () {
      final pairs = OpenSSHKeyPairs(
        cipherName: 'aes256-ctr',
        kdfName: 'bcrypt',
        kdfOptions: OpenSSHBcryptKdfOptions(Uint8List(16), 16),
        publicKeys: [],
        privateKeyBlob: Uint8List(32),
      );
      expect(() => pairs.getPrivateKeys(), throwsA(isA<SSHKeyDecryptError>()));
    });

    test('OpenSSHKeyPairs.getPrivateKeys throws when passphrase provided on unencrypted key', () {
      final pairs = OpenSSHKeyPairs.unencrypted(
        publicKeys: [],
        privateKeyBlob: Uint8List(32),
      );
      expect(
        () => pairs.getPrivateKeys('unneeded-passphrase'),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('OpenSSHKeyPairs and KDF toString work', () {
      final kdf = OpenSSHBcryptKdfOptions(Uint8List.fromList('salt1234'.codeUnits), 16);
      expect(kdf.toString(), contains('salt1234'));

      final pairs = OpenSSHKeyPairs.unencrypted(
        publicKeys: [],
        privateKeyBlob: Uint8List(0),
      );
      expect(pairs.toString(), contains('keys.length: 0'));
      expect(pairs.isEncrypted, isFalse);
    });

    test('OpenSSH keypair toString and comment getters work', () {
      final rsa = SSHKeyPair.fromPem(rsaPrivateOpenSSH).single as OpenSSHRsaKeyPair;
      expect(rsa.toString(), contains('comment:'));
      expect(rsa.comment, isNotNull);
      expect(rsa.shouldProbe, isFalse);

      final ed = SSHKeyPair.fromPem(ed25519Private).single as OpenSSHEd25519KeyPair;
      expect(ed.toString(), contains('comment:'));
      expect(ed.shouldProbe, isFalse);

      final ec = SSHKeyPair.fromPem(ecdsaNistP256Private).single as OpenSSHEcdsaKeyPair;
      expect(ec.toString(), contains('comment:'));
      expect(ec.shouldProbe, isFalse);
    });

    test('RsaKeyPairDEKInfo parse throws on invalid format', () {
      expect(() => RsaKeyPairDEKInfo.parse('invalid'), throwsA(isA<FormatException>()));
    });

    test('RsaKeyPairDEKInfo toString and RsaPrivateKey toString work', () {
      final info = RsaKeyPairDEKInfo('AES-128-CBC', Uint8List(16));
      expect(info.toString(), contains('AES-128-CBC'));

      final rsa = SSHKeyPair.fromPem(rsaPrivate).single as RsaPrivateKey;
      expect(rsa.toString(), contains('version:'));
      expect(rsa.comment, isNull);
      expect(rsa.shouldProbe, isFalse);
    });

    test('RsaKeyPair throws ArgumentError when passphrase is missing on encrypted key', () {
      final pair = RsaKeyPair(RsaKeyPairDEKInfo('AES-128-CBC', Uint8List(16)), Uint8List(32));
      expect(pair.isEncrypted, isTrue);
      expect(() => pair.getPrivateKeys(), throwsA(isA<ArgumentError>()));
    });

    test('EcKeyPair throws ArgumentError when passphrase passed on unencrypted key', () {
      final pair = EcKeyPair(null, Uint8List(32));
      expect(pair.isEncrypted, isFalse);
      expect(() => pair.getPrivateKeys('unneeded'), throwsA(isA<ArgumentError>()));
    });

    test('EcKeyPair throws UnsupportedError for encrypted EC PEM', () {
      final pair = EcKeyPair(RsaKeyPairDEKInfo('DES-EDE3-CBC', Uint8List(8)), Uint8List(32));
      expect(pair.isEncrypted, isTrue);
      expect(() => pair.getPrivateKeys('pass'), throwsA(isA<UnsupportedError>()));
    });
  });
}
