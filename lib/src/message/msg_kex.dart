// ignore_for_file: camel_case_types

import 'dart:typed_data';

import 'package:dartssh4/src/ssh_message.dart';
import 'package:dartssh4/src/utils/list.dart';

class SSH_Message_KexInit implements SSHMessage {
  static const messageId = 20;

  final List<String> kexAlgorithms;
  final List<String> serverHostKeyAlgorithms;
  final List<String> encryptionClientToServer;
  final List<String> encryptionServerToClient;
  final List<String> macClientToServer;
  final List<String> macServerToClient;
  final List<String> compressionClientToServer;
  final List<String> compressionServerToClient;
  final List<String> languagesClientToServer;
  final List<String> languagesServerToClient;
  final bool firstKexPacketFollows;

  SSH_Message_KexInit({
    required this.kexAlgorithms,
    required this.serverHostKeyAlgorithms,
    required this.encryptionClientToServer,
    required this.encryptionServerToClient,
    required this.macClientToServer,
    required this.macServerToClient,
    required this.compressionClientToServer,
    required this.compressionServerToClient,
    this.languagesClientToServer = const [],
    this.languagesServerToClient = const [],
    required this.firstKexPacketFollows,
  });

  factory SSH_Message_KexInit.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1); // skip message id
    reader.skip(16); // skip cookie
    final kexAlgorithms = reader.readNameList();
    final serverHostKeyAlgorithms = reader.readNameList();
    final encryptionClientToServer = reader.readNameList();
    final encryptionServerToClient = reader.readNameList();
    final macClientToServer = reader.readNameList();
    final macServerToClient = reader.readNameList();
    final compressionClientToServer = reader.readNameList();
    final compressionServerToClient = reader.readNameList();
    final languagesClientToServer = reader.readNameList();
    final languagesServerToClient = reader.readNameList();
    final firstKexPacketFollows = reader.readBool();

    return SSH_Message_KexInit(
      firstKexPacketFollows: firstKexPacketFollows,
      kexAlgorithms: kexAlgorithms,
      serverHostKeyAlgorithms: serverHostKeyAlgorithms,
      encryptionClientToServer: encryptionClientToServer,
      encryptionServerToClient: encryptionServerToClient,
      macClientToServer: macClientToServer,
      macServerToClient: macServerToClient,
      compressionClientToServer: compressionClientToServer,
      compressionServerToClient: compressionServerToClient,
      languagesClientToServer: languagesClientToServer,
      languagesServerToClient: languagesServerToClient,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeBytes(randomBytes(16));
    writer.writeNameList(kexAlgorithms);
    writer.writeNameList(serverHostKeyAlgorithms);
    writer.writeNameList(encryptionClientToServer);
    writer.writeNameList(encryptionServerToClient);
    writer.writeNameList(macClientToServer);
    writer.writeNameList(macServerToClient);
    writer.writeNameList(compressionClientToServer);
    writer.writeNameList(compressionServerToClient);
    writer.writeNameList(languagesClientToServer);
    writer.writeNameList(languagesServerToClient);
    writer.writeBool(firstKexPacketFollows);
    writer.writeUint32(0); // reserved
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_KexInit(kexAlgorithms: $kexAlgorithms, serverHostKeyAlgorithms: $serverHostKeyAlgorithms, encryptionClientToServer: $encryptionClientToServer, encryptionServerToClient: $encryptionServerToClient, macClientToServer: $macClientToServer, macServerToClient: $macServerToClient, compressionClientToServer: $compressionClientToServer, compressionServerToClient: $compressionServerToClient, languagesClientToServer: $languagesClientToServer, languagesServerToClient: $languagesServerToClient, firstKexPacketFollows: $firstKexPacketFollows)';
  }
}

class SSH_Message_NewKeys implements SSHMessage {
  static const int messageId = 21;

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_NewKeys()';
  }
}
