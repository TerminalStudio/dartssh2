// ignore_for_file: camel_case_types

import 'dart:typed_data';

import 'package:dartssh2/src/ssh_message.dart';

/// SSH_MSG_UNIMPLEMENTED as defined by RFC 4253 section 11.4.
class SSH_Message_Unimplemented implements SSHMessage {
  static const messageId = 3;

  /// Sequence number of the rejected packet.
  final int sequenceNumber;

  SSH_Message_Unimplemented(this.sequenceNumber);

  factory SSH_Message_Unimplemented.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    return SSH_Message_Unimplemented(reader.readUint32());
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeUint32(sequenceNumber);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_Unimplemented(sequenceNumber: $sequenceNumber)';
  }
}
