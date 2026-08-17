// ignore_for_file: camel_case_types

import 'dart:typed_data';

import 'package:dartssh2/src/ssh_message.dart';

/// SSH_MSG_EXT_INFO as defined in RFC 8308 §2.3.
///
/// Sent by a peer that saw the `ext-info-c` (client) or `ext-info-s` (server)
/// indicator in the other side's SSH_MSG_KEXINIT. It carries a list of
/// extension name/value pairs, of which `server-sig-algs` (RFC 8308 §3.1) is
/// the one clients care about most: it tells the client which public key
/// signature algorithms the server will accept during user authentication.
class SSH_Message_ExtInfo extends SSHMessage {
  static const messageId = 7;

  /// The extensions sent by the peer, keyed by extension name.
  ///
  /// Values are kept as raw bytes because RFC 8308 does not require them to be
  /// UTF-8. Use [serverSigAlgs] for the one extension this client interprets.
  final Map<String, Uint8List> extensions;

  SSH_Message_ExtInfo(this.extensions);

  factory SSH_Message_ExtInfo.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final count = reader.readUint32();
    final extensions = <String, Uint8List>{};
    for (var i = 0; i < count; i++) {
      // A truncated or lying count must not take the connection down: RFC 8308
      // §2.5 requires unrecognised or malformed extensions to be ignored.
      if (reader.isDone) break;
      final name = reader.readUtf8(allowMalformed: true);
      if (reader.isDone) break;
      extensions[name] = reader.readString();
    }
    return SSH_Message_ExtInfo(extensions);
  }

  /// The signature algorithms the server accepts for `publickey`
  /// authentication, or `null` if the server did not send the extension.
  List<String>? get serverSigAlgs {
    final value = extensions['server-sig-algs'];
    if (value == null) return null;
    final names = String.fromCharCodes(value);
    if (names.isEmpty) return const [];
    return names.split(',');
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeUint32(extensions.length);
    for (final entry in extensions.entries) {
      writer.writeUtf8(entry.key);
      writer.writeString(entry.value);
    }
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_ExtInfo(extensions: ${extensions.keys.toList()})';
  }
}
