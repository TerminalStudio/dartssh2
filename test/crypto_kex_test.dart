import 'package:dartssh2/src/kex/kex_dh.dart';
import 'package:dartssh2/src/kex/kex_nist.dart';
import 'package:dartssh2/src/kex/kex_x25519.dart';
import 'package:test/test.dart';

void main() {
  testDH();
  testECDH();
  testX25519();
}

void testDH() {
  test('SSHKexDH.group1', () {
    final kex1 = SSHKexDH.group1();
    final kex2 = SSHKexDH.group1();
    final secret1 = kex1.computeSecret(kex2.e);
    final secret2 = kex2.computeSecret(kex1.e);
    expect(secret1, secret2);
  });

  test('SSHKexDH.group14', () {
    final kex1 = SSHKexDH.group14();
    final kex2 = SSHKexDH.group14();
    final secret1 = kex1.computeSecret(kex2.e);
    final secret2 = kex2.computeSecret(kex1.e);
    expect(secret1, secret2);
  });
}

void testECDH() {
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

void testX25519() {
  test('SSHKexX25519', () {
    final kex1 = SSHKexX25519();
    final kex2 = SSHKexX25519();
    final secret1 = kex1.computeSecret(kex2.publicKey);
    final secret2 = kex2.computeSecret(kex1.publicKey);
    expect(secret1, secret2);
  });
}
