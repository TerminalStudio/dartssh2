// ignore_for_file: camel_case_types

import 'dart:typed_data';

import 'package:dartssh2/src/ssh_message.dart';

class SSH_Message_Service_Request implements SSHMessage {
  static const messageId = 5;

  final String serviceName;

  SSH_Message_Service_Request(this.serviceName);

  factory SSH_Message_Service_Request.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final serviceName = reader.readUtf8();
    return SSH_Message_Service_Request(serviceName);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeUtf8(serviceName);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_Service_Request{serviceName: $serviceName}';
  }
}

class SSH_Message_Service_Accept implements SSHMessage {
  static const messageId = 6;

  final String serviceName;

  SSH_Message_Service_Accept(this.serviceName);

  factory SSH_Message_Service_Accept.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final serviceName = reader.readUtf8();
    return SSH_Message_Service_Accept(serviceName);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeUtf8(serviceName);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_Service_Accept{serviceName: $serviceName}';
  }
}
