import 'dart:typed_data';

import 'package:dartssh3/src/ssh_message.dart';

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
