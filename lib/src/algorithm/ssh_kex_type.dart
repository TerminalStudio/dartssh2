import 'package:dartssh2/src/ssh_algorithm.dart';
import 'package:pointycastle/export.dart';

class SSHKexType extends SSHAlgorithm {
  static const x25519 = SSHKexType._(
    name: 'curve25519-sha256@libssh.org',
    digestFactory: digestSha256,
  );

  static const nistp256 = SSHKexType._(
    name: 'ecdh-sha2-nistp256',
    digestFactory: digestSha256,
  );

  static const nistp384 = SSHKexType._(
    name: 'ecdh-sha2-nistp384',
    digestFactory: digestSha384,
  );

  static const nistp521 = SSHKexType._(
    name: 'ecdh-sha2-nistp521',
    digestFactory: digestSha512,
  );

  static const dhGexSha256 = SSHKexType._(
    name: 'diffie-hellman-group-exchange-sha256',
    digestFactory: digestSha256,
    isGroupExchange: true,
  );

  static const dhGexSha1 = SSHKexType._(
    name: 'diffie-hellman-group-exchange-sha1',
    digestFactory: digestSha1,
    isGroupExchange: true,
  );

  static const dh14Sha1 = SSHKexType._(
    name: 'diffie-hellman-group14-sha1',
    digestFactory: digestSha1,
  );

  static const dh14Sha256 = SSHKexType._(
    name: 'diffie-hellman-group14-sha256',
    digestFactory: digestSha256,
  );

  static const dh1Sha1 = SSHKexType._(
    name: 'diffie-hellman-group1-sha1',
    digestFactory: digestSha1,
  );

  static const dhGroup16Sha512 = SSHKexType._(
    name: 'diffie-hellman-group16-sha512',
    digestFactory: digestSha512,
  );

  static const dhGroup18Sha512 = SSHKexType._(
    name: 'diffie-hellman-group18-sha512',
    digestFactory: digestSha512,
  );

  const SSHKexType._({
    required this.name,
    required this.digestFactory,
    this.isGroupExchange = false,
  });

  /// The name of the algorithm. For example, `"ecdh-sha2-nistp256"`.
  @override
  final String name;

  final Digest Function() digestFactory;

  final bool isGroupExchange;

  Digest createDigest() => digestFactory();
}

Digest digestSha1() => SHA1Digest();
Digest digestSha256() => SHA256Digest();
Digest digestSha384() => SHA384Digest();
Digest digestSha512() => SHA512Digest();
