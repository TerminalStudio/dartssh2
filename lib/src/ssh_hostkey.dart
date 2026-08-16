import 'dart:typed_data';

import 'package:dartssh2/src/ssh_message.dart';

/// Represents an SSH public host key or user public key in SSH wire format.
abstract class SSHHostKey {
  /// Encodes the host key to SSH binary wire format.
  Uint8List encode();

  /// Extracts the key type identifier (e.g., `ssh-rsa`, `ssh-ed25519`,
  /// `ecdsa-sha2-nistp256`) from an [encodedHostKey] binary blob.
  static String getType(Uint8List encodedHostKey) {
    if (encodedHostKey.length < 4) {
      throw ArgumentError('Invalid encoded host key');
    }
    final reader = SSHMessageReader(encodedHostKey);
    return reader.readUtf8();
  }
}

/// Represents an SSH digital signature in SSH wire format.
abstract class SSHSignature {
  /// Encodes the signature to SSH binary wire format.
  Uint8List encode();

  /// Extracts the signature algorithm name from an [encodedSignature] binary blob.
  static String getType(Uint8List encodedSignature) {
    if (encodedSignature.length < 4) {
      throw ArgumentError('Invalid encoded signature');
    }
    final reader = SSHMessageReader(encodedSignature);
    return reader.readUtf8();
  }
}

/// An [SSHHostKey] backed by pre-encoded raw binary wire bytes.
class SSHRawHostKey implements SSHHostKey {
  /// Raw binary bytes of the public key in SSH wire format.
  final Uint8List bytes;

  /// Creates a raw host key from pre-encoded binary [bytes].
  SSHRawHostKey(this.bytes);

  @override
  Uint8List encode() => bytes;
}

/// An [SSHSignature] backed by pre-encoded raw binary wire bytes.
class SSHRawSignature implements SSHSignature {
  /// Raw binary bytes of the signature in SSH wire format.
  final Uint8List bytes;

  /// Creates a raw signature from pre-encoded binary [bytes].
  SSHRawSignature(this.bytes);

  @override
  Uint8List encode() => bytes;
}
