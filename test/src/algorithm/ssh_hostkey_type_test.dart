import 'package:dartssh2/dartssh2.dart';
import 'package:test/test.dart';

void main() {
  group('SSHHostkeyType', () {
    test('Static constants are defined correctly', () {
      expect(SSHHostkeyType.rsaSha1.name, equals('ssh-rsa'));
      expect(SSHHostkeyType.rsaSha256.name, equals('rsa-sha2-256'));
      expect(SSHHostkeyType.rsaSha512.name, equals('rsa-sha2-512'));
      expect(SSHHostkeyType.ecdsa256.name, equals('ecdsa-sha2-nistp256'));
      expect(SSHHostkeyType.ecdsa384.name, equals('ecdsa-sha2-nistp384'));
      expect(SSHHostkeyType.ecdsa521.name, equals('ecdsa-sha2-nistp521'));
      expect(SSHHostkeyType.ed25519.name, equals('ssh-ed25519'));
    });

    test('toString() returns correct format', () {
      expect(
          SSHHostkeyType.rsaSha1.toString(), equals('SSHHostkeyType(ssh-rsa)'));
      expect(SSHHostkeyType.rsaSha256.toString(),
          equals('SSHHostkeyType(rsa-sha2-256)'));
      expect(SSHHostkeyType.rsaSha512.toString(),
          equals('SSHHostkeyType(rsa-sha2-512)'));
      expect(SSHHostkeyType.ecdsa256.toString(),
          equals('SSHHostkeyType(ecdsa-sha2-nistp256)'));
      expect(SSHHostkeyType.ecdsa384.toString(),
          equals('SSHHostkeyType(ecdsa-sha2-nistp384)'));
      expect(SSHHostkeyType.ecdsa521.toString(),
          equals('SSHHostkeyType(ecdsa-sha2-nistp521)'));
      expect(SSHHostkeyType.ed25519.toString(),
          equals('SSHHostkeyType(ssh-ed25519)'));
    });
  });
}
