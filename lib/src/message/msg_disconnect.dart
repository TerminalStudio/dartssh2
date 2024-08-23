// ignore_for_file: camel_case_types

import 'dart:typed_data';

import 'package:dartssh3/src/ssh_message.dart';

class SSH_Message_Disconnect extends SSHMessage {
  static const messageId = 1;

  final int reasonCode;
  final String description;
  final String languageTag;

  SSH_Message_Disconnect({
    required this.reasonCode,
    required this.description,
    this.languageTag = '',
  });

  SSH_Message_Disconnect.fromReason(SSHDisconnectReason reason)
      : reasonCode = reason.code,
        description = reason.description,
        languageTag = '';

  factory SSH_Message_Disconnect.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final reasonCode = reader.readUint32();
    final description = reader.readUtf8();
    final language = reader.readUtf8();
    return SSH_Message_Disconnect(
      reasonCode: reasonCode,
      description: description,
      languageTag: language,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeUint32(reasonCode);
    writer.writeUtf8(description);
    writer.writeUtf8(languageTag);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_Disconnect(reasonCode: $reasonCode, description: $description, language: $languageTag)';
  }
}

enum SSHDisconnectReason {
  hostNotAllowedToConnect,
  protocolError,
  keyExchangeFailed,
  reserved,
  macError,
  compressionError,
  serviceNotAvailable,
  protocolVersionNotSupported,
  hostKeyNotVerifiable,
  connectionLost,
  byApplication,
  tooManyConnections,
  authCancelledByUser,
  noMoreAuthMethodsAvailable,
  illegalUserName,
}

extension SSHDisconnectReasonX on SSHDisconnectReason {
  String get description {
    switch (this) {
      case SSHDisconnectReason.hostNotAllowedToConnect:
        return 'Host not allowed to connect';
      case SSHDisconnectReason.protocolError:
        return 'Protocol error';
      case SSHDisconnectReason.keyExchangeFailed:
        return 'Key exchange failed';
      case SSHDisconnectReason.reserved:
        return 'Reserved';
      case SSHDisconnectReason.macError:
        return 'MAC error';
      case SSHDisconnectReason.compressionError:
        return 'Compression error';
      case SSHDisconnectReason.serviceNotAvailable:
        return 'Service not available';
      case SSHDisconnectReason.protocolVersionNotSupported:
        return 'Protocol version not supported';
      case SSHDisconnectReason.hostKeyNotVerifiable:
        return 'Host key not verifiable';
      case SSHDisconnectReason.connectionLost:
        return 'Connection lost';
      case SSHDisconnectReason.byApplication:
        return 'By application';
      case SSHDisconnectReason.tooManyConnections:
        return 'Too many connections';
      case SSHDisconnectReason.authCancelledByUser:
        return 'Auth cancelled by user';
      case SSHDisconnectReason.noMoreAuthMethodsAvailable:
        return 'No more auth methods available';
      case SSHDisconnectReason.illegalUserName:
        return 'Illegal user name';
    }
  }

  int get code {
    switch (this) {
      case SSHDisconnectReason.hostNotAllowedToConnect:
        return 1;
      case SSHDisconnectReason.protocolError:
        return 2;
      case SSHDisconnectReason.keyExchangeFailed:
        return 3;
      case SSHDisconnectReason.reserved:
        return 4;
      case SSHDisconnectReason.macError:
        return 5;
      case SSHDisconnectReason.compressionError:
        return 6;
      case SSHDisconnectReason.serviceNotAvailable:
        return 7;
      case SSHDisconnectReason.protocolVersionNotSupported:
        return 8;
      case SSHDisconnectReason.hostKeyNotVerifiable:
        return 9;
      case SSHDisconnectReason.connectionLost:
        return 10;
      case SSHDisconnectReason.byApplication:
        return 11;
      case SSHDisconnectReason.tooManyConnections:
        return 12;
      case SSHDisconnectReason.authCancelledByUser:
        return 13;
      case SSHDisconnectReason.noMoreAuthMethodsAvailable:
        return 14;
      case SSHDisconnectReason.illegalUserName:
        return 15;
    }
  }
}
