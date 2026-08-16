import 'dart:typed_data';

import 'package:dartssh2/src/key_pair/openssh_key_pair.dart';
import 'package:dartssh2/src/key_pair/pkcs1_rsa_key_pair.dart';
import 'package:dartssh2/src/key_pair/sec1_ec_key_pair.dart';
import 'package:dartssh2/src/ssh_hostkey.dart';
import 'package:dartssh2/src/ssh_identity.dart';
import 'package:dartssh2/src/ssh_pem.dart';

export 'package:dartssh2/src/key_pair/openssh_key_pair.dart';
export 'package:dartssh2/src/key_pair/pkcs1_rsa_key_pair.dart';
export 'package:dartssh2/src/key_pair/sec1_ec_key_pair.dart';

abstract class SSHKeyPair implements SSHIdentity {
  static List<SSHKeyPair> fromPem(String pemText, [String? passphrase]) {
    final pem = SSHPem.decode(pemText);
    switch (pem.type) {
      case 'OPENSSH PRIVATE KEY':
        final pairs = OpenSSHKeyPairs.decode(pem.content);
        return pairs.getPrivateKeys(passphrase);
      case 'RSA PRIVATE KEY':
        final pair = RsaKeyPair.decode(pem);
        return [pair.getPrivateKeys(passphrase)];
      case 'EC PRIVATE KEY':
        final pair = EcKeyPair.decode(pem);
        return [pair.getPrivateKeys(passphrase)];
      default:
        throw UnsupportedError('Unsupported key type: ${pem.type}');
    }
  }

  static bool isEncryptedPem(String pemText) {
    final pem = SSHPem.decode(pemText);
    switch (pem.type) {
      case 'OPENSSH PRIVATE KEY':
        final pairs = OpenSSHKeyPairs.decode(pem.content);
        return pairs.isEncrypted;
      case 'RSA PRIVATE KEY':
        final pair = RsaKeyPair.decode(pem);
        return pair.isEncrypted;
      case 'EC PRIVATE KEY':
        final pair = EcKeyPair.decode(pem);
        return pair.isEncrypted;
      default:
        throw UnsupportedError('Unsupported key type: ${pem.type}');
    }
  }

  /// [name] is the name of the algorithm used when saving the key. This only
  /// affects how the key is serialized.
  String get name;

  /// [type] indicates not only the encoding of the key, but also the
  /// algorithm used when signing. Until now only RSA keys have [type]s that are
  /// different from [name].
  @override
  String get type;

  @override
  String? get comment => null;

  @override
  bool get shouldProbe => false;

  @override
  SSHHostKey toPublicKey();

  @override
  SSHSignature sign(Uint8List data);

  String toPem();
}
