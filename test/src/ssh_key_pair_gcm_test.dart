import 'dart:io';

import 'package:dartssh2/dartssh2.dart';
import 'package:test/test.dart';

/// Helper function to get the cipher name from an OpenSSH private key
String? getCipherNameFromKey(String pemText) {
  try {
    final pem = SSHPem.decode(pemText);
    if (pem.type == 'OPENSSH PRIVATE KEY') {
      final pairs = OpenSSHKeyPairs.decode(pem.content);
      return pairs.cipherName;
    }
  } catch (e) {
    // If we can't decode, return null
    return null;
  }
  return null;
}

void main() {
  group('OpenSSH GCM Cipher Support Tests', () {
    test('Library supports CBC, CTR, and GCM ciphers', () {
      // List of supported ciphers
      final supportedCiphers = [
        'aes128-ctr',
        'aes192-ctr',
        'aes256-ctr',
        'aes128-cbc',
        'aes192-cbc',
        'aes256-cbc',
        'aes128-gcm@openssh.com',
        'aes256-gcm@openssh.com',
      ];

      // List of unsupported ciphers
      final unsupportedCiphers = [
        'chacha20-poly1305@openssh.com',
      ];

      // Verify supported ciphers can be found
      for (final cipherName in supportedCiphers) {
        final cipher = SSHCipherType.fromName(cipherName);
        expect(cipher, isNotNull, reason: 'Cipher $cipherName should be supported');
        expect(cipher?.name, equals(cipherName));
      }

      // Verify unsupported ciphers cannot be found
      for (final cipherName in unsupportedCiphers) {
        final cipher = SSHCipherType.fromName(cipherName);
        expect(cipher, isNull, reason: 'Cipher $cipherName should not be supported');
      }
    });

    test('GCM ciphers are now supported', () {
      // Verify GCM ciphers can be found and have correct properties
      final gcmCiphers = [
        'aes128-gcm@openssh.com',
        'aes256-gcm@openssh.com',
      ];
      
      for (final cipherName in gcmCiphers) {
        final cipher = SSHCipherType.fromName(cipherName);
        expect(cipher, isNotNull, reason: 'GCM cipher $cipherName should be supported');
        expect(cipher?.name, equals(cipherName));
        expect(cipher?.ivSize, equals(12), reason: 'GCM ciphers use 12-byte IV');
      }
    });

    test('Helper function can detect cipher name from OpenSSH key', () {
      // Test with an existing fixture
      final ed25519Private = fixture('ssh-ed25519/id_ed25519');
      final cipherName = getCipherNameFromKey(ed25519Private);
      
      // Should be able to detect cipher (might be 'none' for unencrypted)
      expect(cipherName, isNotNull);
      print('Detected cipher: $cipherName');
    });

  });

  group('Real-world GCM key test (if available)', () {
    test('Test with actual GCM-encrypted key from environment', () {
      // To use this test:
      // 1. Set GCM_KEY_PATH environment variable to path of your GCM-encrypted key
      // 2. Set GCM_KEY_PASSPHRASE to the passphrase
      // Example: GCM_KEY_PATH=~/.ssh/id_ed25519 GCM_KEY_PASSPHRASE=mypass dart test
      
      final keyPath = Platform.environment['GCM_KEY_PATH'];
      final passphrase = Platform.environment['GCM_KEY_PASSPHRASE'];
      
      if (keyPath != null && File(keyPath).existsSync()) {
        final keyContent = File(keyPath).readAsStringSync();
        final cipherName = getCipherNameFromKey(keyContent);
        
        print('Testing key at: $keyPath');
        print('Detected cipher: $cipherName');
        
        if (cipherName != null && cipherName.contains('gcm')) {
          // This key uses GCM cipher - should work now
          expect(
            () {
              if (passphrase != null) {
                final keyPairs = SSHKeyPair.fromPem(keyContent, passphrase);
                expect(keyPairs, isNotEmpty, reason: 'Should successfully decrypt GCM-encrypted key');
              } else {
                SSHKeyPair.fromPem(keyContent);
              }
            },
            returnsNormally,
            reason: 'Keys encrypted with GCM ciphers should now be supported',
          );
        } else if (cipherName != null && cipherName.contains('chacha20')) {
          // ChaCha20 is still unsupported
          expect(
            () {
              if (passphrase != null) {
                SSHKeyPair.fromPem(keyContent, passphrase);
              } else {
                SSHKeyPair.fromPem(keyContent);
              }
            },
            throwsA(isA<UnsupportedError>().having(
              (e) => e.message,
              'message',
              contains('Unsupported cipher'),
            )),
            reason: 'Keys encrypted with ChaCha20 should still throw UnsupportedError',
          );
        } else {
          print('Key does not use GCM or ChaCha20 cipher, skipping test');
        }
      } else {
        print('GCM_KEY_PATH not set or file not found, skipping test');
        print('To test: GCM_KEY_PATH=/path/to/key GCM_KEY_PASSPHRASE=pass dart test');
      }
    }, skip: Platform.environment['GCM_KEY_PATH'] == null);
  });
}

/// Get the contents of a test fixture.
String fixture(String path) {
  return File('test/fixtures/$path').readAsStringSync();
}

