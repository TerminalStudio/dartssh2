import 'package:dartssh2/dartssh2.dart';
import 'package:test/test.dart';

import '../test_utils.dart';

void main() {
  group('GCM Cipher Integration Tests', () {
    // Test key from fixtures: gcm-test/id_rsa_gcm
    // - Format: OpenSSH format
    // - Cipher: aes256-ctr (or aes256-gcm@openssh.com if converted)
    // - Passphrase: stored in gcm-test/passphrase
    final testKeyContent = fixture('gcm-test/id_rsa_gcm');
    final testPassphrase = fixture('gcm-test/passphrase').trim();

    test('GCM test key should decrypt successfully', () {
      final isEncrypted = SSHKeyPair.isEncryptedPem(testKeyContent);

      expect(isEncrypted, isTrue, reason: 'Test key should be encrypted');

      expect(
        () {
          final keyPairs = SSHKeyPair.fromPem(testKeyContent, testPassphrase);
          expect(keyPairs, isNotEmpty, reason: 'Should successfully decrypt key');
          expect(keyPairs.first, isA<SSHKeyPair>(), reason: 'Should return valid key pair');
          expect(keyPairs.first.name, equals('ssh-rsa'), reason: 'Should be RSA key');
        },
        returnsNormally,
        reason: 'Test key should decrypt successfully',
      );
    });

    test('GCM test key decryption returns valid key pair', () {
      final keyPairs = SSHKeyPair.fromPem(testKeyContent, testPassphrase);
      
      expect(keyPairs, isNotEmpty);
      expect(keyPairs.first.name, equals('ssh-rsa'));
      expect(keyPairs.first.type.toString(), contains('rsa'));
    });
  });
}

