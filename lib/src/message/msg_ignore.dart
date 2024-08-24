// ignore_for_file: camel_case_types

import 'dart:typed_data';

import 'package:dartssh4/src/ssh_message.dart';

class SSH_Message_Ignore extends SSHMessage {
  static const messageId = 2;

  final Uint8List data;

  SSH_Message_Ignore(this.data);

  SSH_Message_Ignore.empty() : data = Uint8List(0);

  factory SSH_Message_Ignore.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final data = reader.readString();
    return SSH_Message_Ignore(data);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeString(data);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_Ignore(data: $data)';
  }
}
