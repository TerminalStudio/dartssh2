import 'package:dartssh2/src/ssh_algorithm.dart';

class SSHHostkeyType extends SSHAlgorithm {
  static const rsaSha1 = SSHHostkeyType._('ssh-rsa');
  static const rsaSha256 = SSHHostkeyType._('rsa-sha2-256');
  static const rsaSha512 = SSHHostkeyType._('rsa-sha2-512');
  static const ecdsa256 = SSHHostkeyType._('ecdsa-sha2-nistp256');
  static const ecdsa384 = SSHHostkeyType._('ecdsa-sha2-nistp384');
  static const ecdsa521 = SSHHostkeyType._('ecdsa-sha2-nistp521');
  static const ed25519 = SSHHostkeyType._('ssh-ed25519');

  const SSHHostkeyType._(this.name);

  /// The name of the algorithm. For example, `"ssh-rsa`"`.
  @override
  final String name;
}
