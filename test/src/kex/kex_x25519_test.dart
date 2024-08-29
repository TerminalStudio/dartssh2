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
}
