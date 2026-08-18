import 'package:dartssh2/src/algorithm/ssh_cipher_type.dart';
import 'package:dartssh2/src/algorithm/ssh_hostkey_type.dart';
import 'package:dartssh2/src/algorithm/ssh_kex_type.dart';
import 'package:dartssh2/src/algorithm/ssh_mac_type.dart';

abstract class SSHAlgorithm {
  /// The name of the algorithm.
  String get name;

  const SSHAlgorithm();

  @override
  String toString() {
    return '$runtimeType($name)';
  }
}

extension SSHAlgorithmList<T extends SSHAlgorithm> on List<T> {
  List<String> toNameList() {
    return map((algorithm) => algorithm.name).toList();
  }

  T? getByName(String name) {
    for (var algorithm in this) {
      if (algorithm.name == name) {
        return algorithm;
      }
    }
    return null;
  }
}

class SSHAlgorithms {
  /// Algorithm used for the key exchange.
  final List<SSHKexType> kex;

  /// Algorithm used for the host key.
  final List<SSHHostkeyType> hostkey;

  /// Algorithm used for the encryption.
  final List<SSHCipherType> cipher;

  /// Algorithm used for the authentication.
  final List<SSHMacType> mac;

  /// Creates an algorithm preference set.
  ///
  /// Every list is ordered by preference: the first entry that the peer also
  /// supports is the one that gets negotiated (RFC 4253 §7.1). The defaults
  /// put the strongest algorithm first and keep weaker ones only as a
  /// last-resort fallback for old servers.
  ///
  /// Algorithms considered broken are not in the defaults at all, but they are
  /// still implemented and can be re-enabled explicitly. `diffie-hellman-
  /// group1-sha1` (1024-bit DH), `hmac-md5`, and the truncated
  /// `hmac-sha2-[256|512]-96` variants fall in that group.
  const SSHAlgorithms({
    this.kex = const [
      SSHKexType.x25519Rfc,
      SSHKexType.x25519,
      SSHKexType.nistp521,
      SSHKexType.nistp384,
      SSHKexType.nistp256,
      SSHKexType.dhGexSha256,
      SSHKexType.dh14Sha256,
      // SHA-1 based key exchange is kept last for old servers only.
      SSHKexType.dh14Sha1,
      SSHKexType.dhGexSha1,
    ],
    this.hostkey = const [
      SSHHostkeyType.ed25519,
      SSHHostkeyType.rsaSha512,
      SSHHostkeyType.rsaSha256,
      SSHHostkeyType.ecdsa521,
      SSHHostkeyType.ecdsa384,
      SSHHostkeyType.ecdsa256,
      // `ssh-rsa` signs with SHA-1. OpenSSH disabled it by default in 8.8, so
      // it is only reached when the server offers nothing better.
      SSHHostkeyType.rsaSha1,
    ],
    this.cipher = const [
      SSHCipherType.aes256gcm,
      SSHCipherType.aes128gcm,
      SSHCipherType.chacha20poly1305,
      SSHCipherType.aes256ctr,
      SSHCipherType.aes128ctr,
      // CBC in SSH is vulnerable to the plaintext-recovery attack described in
      // CVE-2008-5161. Kept last so it is only used when nothing else matches.
      SSHCipherType.aes256cbc,
      SSHCipherType.aes128cbc,
    ],
    this.mac = const [
      // Encrypt-then-MAC is preferred over the encrypt-and-MAC variants.
      SSHMacType.hmacSha256Etm,
      SSHMacType.hmacSha512Etm,
      SSHMacType.hmacSha256,
      SSHMacType.hmacSha512,
      SSHMacType.hmacSha1,
    ],
  });
}
