import 'dart:io';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:test/test.dart';

import '../test_utils.dart';

// extension StringReadAsFile on String {
//   String readFile() => File(this).readAsStringSync();
// }

void main() {
  final rsaPrivate = fixture('ssh-rsa/id_rsa');
  final rsaPrivateOpenSSH = fixture('ssh-rsa/id_rsa.openssh');

  final rsaPrivateEncrypted = fixture('ssh-rsa-passphrase/id_rsa');
  final rsaPassphrase = fixture('ssh-rsa-passphrase/passphrase');

  final ecdsaNistP256Private = fixture('ecdsa-sha2-nistp256/id_ecdsa');
  // final ecdsaNistP384Private = fixture('ecdsa-sha2-nistp384/id_ecdsa');
  // final ecdsaNistP521Private = fixture('ecdsa-sha2-nistp521/id_ecdsa');

  final ed25519Private = fixture('ssh-ed25519/id_ed25519');
  final ed25519PrivateEncrypted = fixture('ssh-ed25519-passphrase/id_ed25519');
  final ed25519PrivatePassphrase = fixture('ssh-ed25519-passphrase/passphrase');

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

  test('SSHKeyPair.fromPem works with Ed25519 private key', () async {
    final pem = ed25519Private;
    final keypairs = SSHKeyPair.fromPem(pem);
    expect(keypairs.length, 1);
    expect(keypairs.single, isA<OpenSSHEd25519KeyPair>());
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
}
