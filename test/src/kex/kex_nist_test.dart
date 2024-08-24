import 'package:dartssh3/src/kex/kex_nist.dart';
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
}
