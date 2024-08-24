// ignore_for_file: camel_case_types

import 'dart:typed_data';

import 'package:dartssh3/src/ssh_message.dart';

class SSH_Message_Debug implements SSHMessage {
  static const messageId = 4;

  final bool alwaysDisplay;

  final Uint8List message;

  final Uint8List language;

  SSH_Message_Debug({
    required this.alwaysDisplay,
    required this.message,
    required this.language,
  });

  factory SSH_Message_Debug.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final alwaysDisplay = reader.readBool();
    final message = reader.readString();
    final language = reader.readString();
    return SSH_Message_Debug(
      alwaysDisplay: alwaysDisplay,
      message: message,
      language: language,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeBool(alwaysDisplay);
    writer.writeString(message);
    writer.writeString(language);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_Debug(alwaysDisplay: $alwaysDisplay, message: $message, language: $language)';
  }
}
