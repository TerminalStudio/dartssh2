// ignore_for_file: camel_case_types

import 'dart:typed_data';

import 'package:dartssh3/src/ssh_message.dart';

class SSH_Message_KexDH_Init implements SSHMessage {
  static const messageId = 30;

  /// Client generates a random number x (1 < x < q) and computes e = g^x mod p
  final BigInt e;

  SSH_Message_KexDH_Init({required this.e});

  factory SSH_Message_KexDH_Init.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1); // skip message number
    final e = reader.readMpint();
    return SSH_Message_KexDH_Init(e: e);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeMpint(e);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_KexDH_Init(e: $e)';
  }
}

class SSH_Message_KexDH_Reply implements SSHMessage {
  static const messageId = 31;

  /// server public host key and certificates (K_S)
  final Uint8List hostPublicKey;

  /// Server generates a random number y (0 < y < q) and computes f = g^y mod p.
  final BigInt f;

  /// The signature on the exchange hash H
  final Uint8List signature;

  SSH_Message_KexDH_Reply({
    required this.hostPublicKey,
    required this.f,
    required this.signature,
  });

  factory SSH_Message_KexDH_Reply.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1); // skip message number
    final publicKey = reader.readString();
    final f = reader.readMpint();
    final signature = reader.readString();
    return SSH_Message_KexDH_Reply(
      hostPublicKey: publicKey,
      f: f,
      signature: signature,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeString(hostPublicKey);
    writer.writeMpint(f);
    writer.writeString(signature);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_KexDH_Reply(hostPublicKey: $hostPublicKey, f: $f, signature: $signature)';
  }
}

class SSH_Message_KexDH_GexRequest implements SSHMessage {
  static const messageId = 34;

  final int minN;
  final int preferredN;
  final int maxN;

  SSH_Message_KexDH_GexRequest({
    required this.minN,
    required this.preferredN,
    required this.maxN,
  });

  factory SSH_Message_KexDH_GexRequest.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1); // skip message number
    final minN = reader.readUint32();
    final preferredN = reader.readUint32();
    final maxN = reader.readUint32();
    return SSH_Message_KexDH_GexRequest(
      minN: minN,
      preferredN: preferredN,
      maxN: maxN,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeUint32(minN);
    writer.writeUint32(preferredN);
    writer.writeUint32(maxN);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_KexDH_GexRequest(minN: $minN, preferredN: $preferredN, maxN: $maxN)';
  }
}

class SSH_Message_KexDH_GexGroup extends SSHMessage {
  static const messageId = 31;

  final BigInt p;
  final BigInt g;

  SSH_Message_KexDH_GexGroup({
    required this.p,
    required this.g,
  });

  factory SSH_Message_KexDH_GexGroup.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1); // skip message number
    final p = reader.readMpint();
    final g = reader.readMpint();
    return SSH_Message_KexDH_GexGroup(p: p, g: g);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeMpint(p);
    writer.writeMpint(g);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return '$runtimeType(p: $p, g: $g)';
  }
}

class SSH_Message_KexDH_GexInit implements SSHMessage {
  static const messageId = 32;

  /// Client generates a random number x (1 < x < q) and computes e = g^x mod p
  final BigInt e;

  SSH_Message_KexDH_GexInit({required this.e});

  factory SSH_Message_KexDH_GexInit.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1); // skip message number
    final e = reader.readMpint();
    return SSH_Message_KexDH_GexInit(e: e);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeMpint(e);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_KexDH_Init(e: $e)';
  }
}

class SSH_Message_KexDH_GexReply implements SSH_Message_KexDH_Reply {
  static const messageId = 33;

  /// server public host key and certificates (K_S)
  @override
  final Uint8List hostPublicKey;

  /// Server generates a random number y (0 < y < q) and computes f = g^y mod p.
  @override
  final BigInt f;

  /// The signature on the exchange hash H
  @override
  final Uint8List signature;

  SSH_Message_KexDH_GexReply({
    required this.hostPublicKey,
    required this.f,
    required this.signature,
  });

  factory SSH_Message_KexDH_GexReply.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1); // skip message number
    final publicKey = reader.readString();
    final f = reader.readMpint();
    final signature = reader.readString();
    return SSH_Message_KexDH_GexReply(
      hostPublicKey: publicKey,
      f: f,
      signature: signature,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeString(hostPublicKey);
    writer.writeMpint(f);
    writer.writeString(signature);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return '$runtimeType(hostPublicKey: $hostPublicKey, f: $f, signature: $signature)';
  }
}
