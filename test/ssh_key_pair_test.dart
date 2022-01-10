import 'dart:io';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:test/test.dart';

void main() {
  final rsaPrivate = 'test/ssh-rsa/id_rsa';
  final rsaPrivateOpenSSH = 'test/ssh-rsa/id_rsa.openssh';

  final ecdsaNistP256Private = 'test/ecdsa-sha2-nistp256/id_ecdsa';
  // final ecdsaNistP384Private = 'test/ecdsa-sha2-nistp384/id_ecdsa';
  // final ecdsaNistP521Private = 'test/ecdsa-sha2-nistp521/id_ecdsa';

  final ed25519Private = 'test/ssh-ed25519/id_ed25519';
  final ed25519PrivateEncrypted = 'test/ssh-ed25519-passphrase/id_ed25519';
  final ed25519PrivatePassphrase = 'test/ssh-ed25519-passphrase/passphrase';

  test('SSHKeyPair.fromPem', () async {
    final pem = await File(ed25519Private).readAsString();
    final keypairs = SSHKeyPair.fromPem(pem);
    expect(keypairs.length, 1);
    expect(keypairs.single, isA<OpenSSHEd25519KeyPair>());
  });

  test('SSHKeyPair.isEncryptedPem', () async {
    final pem = await File(ed25519Private).readAsString();
    final pemEncrypted = await File(ed25519PrivateEncrypted).readAsString();
    expect(SSHKeyPair.isEncryptedPem(pem), false);
    expect(SSHKeyPair.isEncryptedPem(pemEncrypted), true);
  });

  test('SSHKeyPair.fromPem with passphrase', () async {
    final pem = await File(ed25519PrivateEncrypted).readAsString();
    final passphrase = await File(ed25519PrivatePassphrase).readAsString();
    final keypairs = SSHKeyPair.fromPem(pem, passphrase);
    expect(keypairs.length, 1);
    expect(keypairs.single, isA<OpenSSHEd25519KeyPair>());
  });

  test('SSHKeyPair.fromPem with passphrase throws', () async {
    final pem = await File(ed25519PrivateEncrypted).readAsString();
    final passphrase = 'wrong';
    expect(() => SSHKeyPair.fromPem(pem, passphrase), throwsA(isA<SSHError>()));
  });

  test('RsaKeyPair.toPem() works', () async {
    final pem = await File(rsaPrivate).readAsString();
    final keypair = SSHKeyPair.fromPem(pem).single;
    expect(keypair.toPem(), pem);
  });

  test('OpenSSHRsaKeyPair.toPem() works', () async {
    final pem1 = await File(rsaPrivateOpenSSH).readAsString();
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
    final pem1 = await File(ecdsaNistP256Private).readAsString();
    final keypair1 = SSHKeyPair.fromPem(pem1).single as OpenSSHEcdsaKeyPair;

    final pem2 = keypair1.toPem();
    final keypair2 = SSHKeyPair.fromPem(pem2).single as OpenSSHEcdsaKeyPair;

    expect(pem1.length, pem2.length);

    expect(keypair1.curveId, keypair2.curveId);
    expect(keypair1.d, keypair2.d);
    expect(keypair1.q, keypair2.q);
  });

  test('OpenSSHEd25519KeyPair.toPem() works', () async {
    final pem1 = await File(ed25519Private).readAsString();
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
