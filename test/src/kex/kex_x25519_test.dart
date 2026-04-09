import 'dart:typed_data';

import 'package:dartssh2/src/kex/kex_x25519.dart';
import 'package:test/test.dart';

void main() {
  test('SSHKexX25519', () {
    final kex1 = SSHKexX25519();
    final kex2 = SSHKexX25519();
    final secret1 = kex1.computeSecret(kex2.publicKey);
    final secret2 = kex2.computeSecret(kex1.publicKey);
    expect(secret1, secret2);
  });
  group('SSHKexX25519', () {
    late SSHKexX25519 kex;

    setUp(() {
      kex = SSHKexX25519();
    });

    test('should generate a 32-byte private key', () {
      expect(kex.privateKey.length, equals(32));
    });

    test('should generate a 32-byte public key', () {
      expect(kex.publicKey.length, equals(32));
    });

    test('should compute shared secret correctly', () {
      // Generate a new SSHKexX25519 instance to act as the remote party
      final remoteKex = SSHKexX25519();

      // Compute the shared secret using the local private key and remote public key
      final sharedSecret = kex.computeSecret(remoteKex.publicKey);

      // Compute the shared secret using the remote private key and local public key
      final remoteSharedSecret = remoteKex.computeSecret(kex.publicKey);

      // Assert that both shared secrets are equal
      expect(sharedSecret, equals(remoteSharedSecret));
    });

    test('should handle invalid public key length in computeSecret', () {
      final invalidPublicKey = Uint8List(31); // Invalid length

      expect(() => kex.computeSecret(invalidPublicKey),
          throwsA(isA<ArgumentError>()));
    });

    test('should handle valid inputs for scalar multiplication indirectly', () {
      // This test is intended to indirectly verify the behavior of scalar multiplication
      // through the public method computeSecret.

      final validPublicKey = kex.publicKey;

      // Test valid scenario using computeSecret
      final validKex = SSHKexX25519();
      final validSharedSecret = validKex.computeSecret(validPublicKey);

      expect(validSharedSecret, isNotNull);
      expect(validSharedSecret.bitLength, greaterThan(0));
    });
  });
}
