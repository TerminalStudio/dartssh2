import 'package:dartssh2/src/algorithm/ssh_cipher_type.dart';
import 'package:dartssh2/src/algorithm/ssh_hostkey_type.dart';
import 'package:dartssh2/src/algorithm/ssh_kex_type.dart';
import 'package:dartssh2/src/algorithm/ssh_mac_type.dart';

abstract class SSHAlgorithm {
  String get name;

  const SSHAlgorithm();

  // RFC 4251: algorithm identifiers MUST be printable US-ASCII,
  // non-empty strings no longer than 64 characters
  bool get isValidAlgorithmName {
    if (name.isEmpty || name.length > 64) return false;

    // Check for printable US-ASCII (32-126, excluding DEL 127)
    for (int i = 0; i < name.length; i++) {
      int code = name.codeUnitAt(i);
      if (code <= 32 || code >= 127) return false;
    }

    // RFC 4251: Names MUST NOT contain comma, whitespace, control characters
    if (name.contains(',') || name.contains(' ') || name.contains('\t')) {
      return false;
    }

    // Check @ format rule
    final atIndex = name.indexOf('@');
    if (atIndex != -1) {
      // Must have only a single @ sign
      if (name.indexOf('@', atIndex + 1) != -1) return false;

      // Part after @ must be valid domain name
      final domain = name.substring(atIndex + 1);
      if (!_isValidDomainName(domain)) return false;
    }

    return true;
  }

  bool _isValidDomainName(String domain) {
    // Basic domain name validation
    if (domain.isEmpty) return false;
    final parts = domain.split('.');
    if (parts.length < 2) return false;

    for (final part in parts) {
      if (part.isEmpty) return false;
      if (!RegExp(r'^[a-zA-Z0-9-]+$').hasMatch(part)) return false;
      if (part.startsWith('-') || part.endsWith('-')) return false;
    }

    return true;
  }

  @override
  String toString() {
    assert(isValidAlgorithmName, 'Invalid algorithm name: $name');
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

  const SSHAlgorithms({
    // Prefer modern KEX first; move legacy SHA-1/group1 variants to the end
    // as fallback-only to improve security defaults.
    this.kex = const [
      SSHKexType.x25519,
      SSHKexType.nistp521,
      SSHKexType.nistp384,
      SSHKexType.nistp256,
      SSHKexType.dh16Sha512,
      SSHKexType.dh14Sha256,
      SSHKexType.dhGexSha256,
      // Legacy fallbacks (SHA-1/group1)
      SSHKexType.dh14Sha1,
      SSHKexType.dhGexSha1,
      SSHKexType.dh1Sha1,
    ],
    this.hostkey = const [
      SSHHostkeyType.ed25519,
      SSHHostkeyType.ecdsa521,
      SSHHostkeyType.ecdsa384,
      SSHHostkeyType.ecdsa256,
      SSHHostkeyType.rsaSha512,
      SSHHostkeyType.rsaSha256,
      // Legacy fallback
      SSHHostkeyType.rsaSha1,
    ],

    /// Prefer AES-GCM/CTR first for compatibility; keep ChaCha20-Poly1305
    /// available but lower priority until its transport implementation fully
    /// stabilises. CBC remains as legacy fallback only.
    this.cipher = const [
      // Prioritise widely-supported CTR modes for compatibility
      SSHCipherType.aes256ctr,
      SSHCipherType.aes128ctr,
      // Offer AEAD modes once interoperability improves
      SSHCipherType.aes256gcm,
      SSHCipherType.aes128gcm,
      SSHCipherType.chacha20poly1305,
      // Legacy fallbacks (CBC)
      SSHCipherType.aes256cbc,
      SSHCipherType.aes128cbc,
    ],
    // Prefer modern SHA-2 MACs by default; full-length variants first,
    // ETM variants for better security, truncated 96-bit as last-resort fallback.
    this.mac = const [
      SSHMacType.hmacSha256Etm,
      SSHMacType.hmacSha512Etm,
      SSHMacType.hmacSha256,
      SSHMacType.hmacSha512,
      SSHMacType.hmacSha1,
      SSHMacType.hmacMd5,
      SSHMacType.hmacSha256_96,
      SSHMacType.hmacSha512_96,
    ],
  });
}
