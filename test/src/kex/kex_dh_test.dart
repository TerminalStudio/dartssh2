import 'package:dartssh2/src/kex/kex_dh.dart';
import 'package:test/test.dart';

void main() {
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
