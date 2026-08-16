import 'dart:typed_data';

import 'package:dartssh2/src/ssh_message.dart';

abstract class SSHHostKey {
  /// Encode the host key to SSH encoded data.
  Uint8List encode();

  static String getType(Uint8List encodedHostKey) {
    if (encodedHostKey.length < 4) {
      throw ArgumentError('Invalid encoded host key');
    }
    final reader = SSHMessageReader(encodedHostKey);
    return reader.readUtf8();
  }
}

abstract class SSHSignature {
  /// Encode the signature to SSH encoded data.
  Uint8List encode();

  static String getType(Uint8List encodedSignature) {
    if (encodedSignature.length < 4) {
      throw ArgumentError('Invalid encoded signature');
    }
    final reader = SSHMessageReader(encodedSignature);
    return reader.readUtf8();
  }
}

/// An [SSHHostKey] backed by pre-encoded raw bytes.
class SSHRawHostKey implements SSHHostKey {
  final Uint8List bytes;

  SSHRawHostKey(this.bytes);

  @override
  Uint8List encode() => bytes;
}

/// An [SSHSignature] backed by pre-encoded raw bytes.
class SSHRawSignature implements SSHSignature {
  final Uint8List bytes;

  SSHRawSignature(this.bytes);

  @override
  Uint8List encode() => bytes;
}
