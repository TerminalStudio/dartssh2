import 'package:dartssh2/dartssh2.dart';
import 'package:pointycastle/export.dart';
import 'package:test/test.dart';

void main() {
  group('SSHKexType', () {
    test('Static constants are defined correctly', () {
      expect(SSHKexType.x25519.name, equals('curve25519-sha256@libssh.org'));
      expect(SSHKexType.nistp256.name, equals('ecdh-sha2-nistp256'));
      expect(SSHKexType.nistp384.name, equals('ecdh-sha2-nistp384'));
      expect(SSHKexType.nistp521.name, equals('ecdh-sha2-nistp521'));
      expect(SSHKexType.dhGexSha256.name,
          equals('diffie-hellman-group-exchange-sha256'));
      expect(SSHKexType.dhGexSha1.name,
          equals('diffie-hellman-group-exchange-sha1'));
      expect(SSHKexType.dh14Sha1.name, equals('diffie-hellman-group14-sha1'));
      expect(
          SSHKexType.dh14Sha256.name, equals('diffie-hellman-group14-sha256'));
      expect(SSHKexType.dh1Sha1.name, equals('diffie-hellman-group1-sha1'));
    });

    test(
        'Static constants have correct digestFactory and isGroupExchange values',
        () {
      expect(SSHKexType.x25519.digestFactory, equals(digestSha256));
      expect(SSHKexType.nistp256.digestFactory, equals(digestSha256));
      expect(SSHKexType.nistp384.digestFactory, equals(digestSha384));
      expect(SSHKexType.nistp521.digestFactory, equals(digestSha512));
      expect(SSHKexType.dhGexSha256.digestFactory, equals(digestSha256));
      expect(SSHKexType.dhGexSha1.digestFactory, equals(digestSha1));
      expect(SSHKexType.dh14Sha1.digestFactory, equals(digestSha1));
      expect(SSHKexType.dh14Sha256.digestFactory, equals(digestSha256));
      expect(SSHKexType.dh1Sha1.digestFactory, equals(digestSha1));

      expect(SSHKexType.dhGexSha256.isGroupExchange, isTrue);
      expect(SSHKexType.dhGexSha1.isGroupExchange, isTrue);
      expect(SSHKexType.dh14Sha1.isGroupExchange, isFalse);
      expect(SSHKexType.dh14Sha256.isGroupExchange, isFalse);
      expect(SSHKexType.dh1Sha1.isGroupExchange, isFalse);
    });

    test('createDigest() returns correct Digest instance', () {
      final kexType = SSHKexType.x25519;
      final digest = kexType.createDigest();
      expect(digest, isA<SHA256Digest>());
    });

    test(
        'createDigest() returns correct Digest instance for different algorithms',
        () {
      final kexTypeSha1 = SSHKexType.dhGexSha1;
      final digestSha1 = kexTypeSha1.createDigest();
      expect(digestSha1, isA<SHA1Digest>());

      final kexTypeSha256 = SSHKexType.dhGexSha256;
      final digestSha256 = kexTypeSha256.createDigest();
      expect(digestSha256, isA<SHA256Digest>());

      final kexTypeSha384 = SSHKexType.nistp384;
      final digestSha384 = kexTypeSha384.createDigest();
      expect(digestSha384, isA<SHA384Digest>());

      final kexTypeSha512 = SSHKexType.nistp521;
      final digestSha512 = kexTypeSha512.createDigest();
      expect(digestSha512, isA<SHA512Digest>());
    });
  });
}
