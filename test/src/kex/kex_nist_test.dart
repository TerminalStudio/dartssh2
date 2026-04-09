import 'package:dartssh2/src/kex/kex_nist.dart';
import 'package:test/test.dart';

void main() {
  test('SSHKexECDH.nistp256', () {
    final kex1 = SSHKexNist.p256();
    final kex2 = SSHKexNist.p256();
    final secret1 = kex1.computeSecret(kex2.publicKey);
    final secret2 = kex2.computeSecret(kex1.publicKey);
    expect(secret1, secret2);
  });

  test('SSHKexECDH.nistp384', () {
    final kex1 = SSHKexNist.p384();
    final kex2 = SSHKexNist.p384();
    final secret1 = kex1.computeSecret(kex2.publicKey);
    final secret2 = kex2.computeSecret(kex1.publicKey);
    expect(secret1, secret2);
  });

  test('SSHKexECDH.nistp521', () {
    final kex1 = SSHKexNist.p521();
    final kex2 = SSHKexNist.p521();
    final secret1 = kex1.computeSecret(kex2.publicKey);
    final secret2 = kex2.computeSecret(kex1.publicKey);
    expect(secret1, secret2);
  });

  group('SSHKexNist', () {
    test('generate keys and compute shared secret (P-256)', () {
      final kex = SSHKexNist.p256();
      final remoteKex = SSHKexNist.p256();

      final secret1 = kex.computeSecret(remoteKex.publicKey);
      final secret2 = remoteKex.computeSecret(kex.publicKey);

      expect(secret1, equals(secret2), reason: 'Shared secrets do not match.');
    });

    test('generate keys and compute shared secret (P-384)', () {
      final kex = SSHKexNist.p384();
      final remoteKex = SSHKexNist.p384();

      final secret1 = kex.computeSecret(remoteKex.publicKey);
      final secret2 = remoteKex.computeSecret(kex.publicKey);

      expect(secret1, equals(secret2), reason: 'Shared secrets do not match.');
    });

    test('generate keys and compute shared secret (P-521)', () {
      final kex = SSHKexNist.p521();
      final remoteKex = SSHKexNist.p521();

      final secret1 = kex.computeSecret(remoteKex.publicKey);
      final secret2 = remoteKex.computeSecret(kex.publicKey);

      expect(secret1, equals(secret2), reason: 'Shared secrets do not match.');
    });

    test('generate private key within valid range', () {
      final kex = SSHKexNist.p256();
      final privateKey = kex.privateKey;

      expect(privateKey, isNot(equals(BigInt.zero)),
          reason: 'Private key should not be zero.');
      expect(privateKey < kex.curve.n, isTrue,
          reason: 'Private key should be less than curve order.');
    });
  });
}
