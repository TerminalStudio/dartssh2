// ignore_for_file: camel_case_types

import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dartssh2/src/ssh_message.dart';

class SSH_Message_KexECDH_Init implements SSHMessage {
  static const messageId = 30;

  /// Client generates a random number x (1 < x < q) and computes e = g^x mod p
  final Uint8List ecdhPublicKey;

  SSH_Message_KexECDH_Init(this.ecdhPublicKey);

  factory SSH_Message_KexECDH_Init.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1); // skip message number
    final publicKey = reader.readString();
    return SSH_Message_KexECDH_Init(publicKey);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeString(ecdhPublicKey);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_KexECDH_Init(publicKey: ${hex.encode(ecdhPublicKey)})';
  }
}

class SSH_Message_KexECDH_Reply implements SSHMessage {
  static const messageId = 31;

  /// Server public host key and certificates (K_S)
  final Uint8List hostPublicKey;

  /// Server's ephemeral public key octet string (Q_S)
  final Uint8List ecdhPublicKey;

  /// The signature on the exchange hash H
  final Uint8List signature;

  SSH_Message_KexECDH_Reply({
    required this.hostPublicKey,
    required this.ecdhPublicKey,
    required this.signature,
  });

  factory SSH_Message_KexECDH_Reply.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1); // skip message number
    final hostPublicKey = reader.readString();
    final ecdhPublicKey = reader.readString();
    final signature = reader.readString();
    return SSH_Message_KexECDH_Reply(
      ecdhPublicKey: ecdhPublicKey,
      hostPublicKey: hostPublicKey,
      signature: signature,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeString(ecdhPublicKey);
    writer.writeString(hostPublicKey);
    writer.writeString(signature);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_KexECDH_Reply(hostPublicKey: ${hex.encode(hostPublicKey)}, ecdhPublicKey: ${hex.encode(ecdhPublicKey)}, signature: ${hex.encode(signature)})';
  }
}
