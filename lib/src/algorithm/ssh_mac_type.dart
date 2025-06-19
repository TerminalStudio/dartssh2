import 'dart:typed_data';

import 'package:dartssh2/src/ssh_algorithm.dart';
import 'package:pointycastle/export.dart';

import '../utils/truncated_hmac.dart';

class SSHMacType extends SSHAlgorithm {
  static const hmacMd5 = SSHMacType._(
    name: 'hmac-md5',
    keySize: 16,
    macFactory: _hmacMd5Factory,
  );

  static const hmacSha1 = SSHMacType._(
    name: 'hmac-sha1',
    keySize: 20,
    macFactory: _hmacSha1Factory,
  );

  static const hmacSha256 = SSHMacType._(
    name: 'hmac-sha2-256',
    keySize: 32,
    macFactory: _hmacSha256Factory,
  );

  static const hmacSha512 = SSHMacType._(
    name: 'hmac-sha2-512',
    keySize: 64,
    macFactory: _hmacSha512Factory,
  );

  // added by Rein
  static const hmacSha256_96 = SSHMacType._(
    name: 'hmac-sha2-256-96',
    keySize: 32,
    macFactory: _hmacSha256_96Factory,
  );

  static const hmacSha512_96 = SSHMacType._(
    name: 'hmac-sha2-512-96',
    keySize: 64,
    macFactory: _hmacSha512_96Factory,
  );

  static const hmacSha256Etm = SSHMacType._(
    name: 'hmac-sha2-256-etm@openssh.com',
    keySize: 32,
    macFactory: _hmacSha256Factory,
    isEtm: true,
  );

  static const hmacSha512Etm = SSHMacType._(
    name: 'hmac-sha2-512-etm@openssh.com',
    keySize: 64,
    macFactory: _hmacSha512Factory,
    isEtm: true,
  );
  // end added by Rein
  const SSHMacType._({
    required this.name,
    required this.keySize,
    required this.macFactory,
    this.isEtm = false,
  });

  @override
  final String name;

  final int keySize;

  final Mac Function() macFactory;

  /// Whether this MAC algorithm is an ETM (Encrypt-Then-MAC) variant.
  final bool isEtm;

  Mac createMac(Uint8List key) {
    if (key.length != keySize) {
      throw ArgumentError.value(key, 'key', 'Key must be $keySize bytes long');
    }

    final mac = macFactory();
    mac.init(KeyParameter(key));
    return mac;
  }
}

Mac _hmacMd5Factory() {
  return HMac(MD5Digest(), 64);
}

Mac _hmacSha1Factory() {
  return HMac(SHA1Digest(), 64);
}

Mac _hmacSha256Factory() {
  return HMac(SHA256Digest(), 64);
}

Mac _hmacSha512Factory() {
  return HMac(SHA512Digest(), 128);
}

Mac _hmacSha256_96Factory() {
  return TruncatedHMac(SHA256Digest(), 64, 12);
}

Mac _hmacSha512_96Factory() {
  return TruncatedHMac(SHA512Digest(), 128, 12);
}
