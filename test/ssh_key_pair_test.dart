import 'dart:io';

import 'package:dartssh2/dartssh2.dart';
import 'package:test/test.dart';

void main() {
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
}
