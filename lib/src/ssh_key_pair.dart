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

/// Base interface for in-memory SSH cryptographic key pairs.
///
/// Implements [SSHIdentity] for authentication and provides factory methods to
/// parse OpenSSH, PKCS#1 RSA, and SEC1 EC private key formats.
abstract class SSHKeyPair implements SSHIdentity {
  /// Decodes one or more [SSHKeyPair] instances from [pemText].
  ///
  /// If the private key is encrypted, [passphrase] is required.
  /// Supported formats:
  /// - `OPENSSH PRIVATE KEY` (OpenSSH format, including bcrypt KDF)
  /// - `RSA PRIVATE KEY` (PKCS#1 format)
  /// - `EC PRIVATE KEY` (SEC1 format)
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

  /// Determines whether the private key in [pemText] is passphrase-protected.
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

  /// The algorithm name used when serializing the key (e.g., `ssh-rsa`,
  /// `ssh-ed25519`, `ecdsa-sha2-nistp256`).
  String get name;

  /// The signature algorithm name used when signing challenges.
  @override
  String get type;

  /// In-memory key pairs do not use comment probing by default.
  @override
  String? get comment => null;

  /// In-memory key pairs do not require probing by default since signing is
  /// local and synchronous.
  @override
  bool get shouldProbe => false;

  /// Exports the public key portion of this key pair as an [SSHHostKey].
  @override
  SSHHostKey toPublicKey();

  /// Synchronously signs binary [data] with this private key.
  @override
  SSHSignature sign(Uint8List data);

  /// Encodes this key pair into PEM string format.
  String toPem();
}
