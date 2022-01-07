// ignore_for_file: camel_case_types

import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dartssh2/src/ssh_message.dart';

class SSH_Message_Global_Request extends SSHMessage {
  static const messageId = 80;

  final String requestName;
  final bool wantReply;

  /// "tcpip-forward" and "cancel-tcpip-forward" request specific data
  final String? bindAddress;
  final int? bindPort;

  // // "hostkeys-00@openssh.com" request specific data.
  // final List<SSHHostKey>? hostKeys;

  SSH_Message_Global_Request({
    required this.requestName,
    required this.wantReply,
    this.bindAddress,
    this.bindPort,
    // this.hostKeys,
  });

  /// Request connections to the other side be forwarded to the local side
  factory SSH_Message_Global_Request.tcpipForward(
    String bindAddress,
    int bindPort,
  ) {
    return SSH_Message_Global_Request(
      requestName: 'tcpip-forward',
      wantReply: true,
      bindAddress: bindAddress,
      bindPort: bindPort,
    );
  }

  /// Request cancellation of a port forwarding
  factory SSH_Message_Global_Request.cancelTcpipForward({
    required String bindAddress,
    required int bindPort,
  }) {
    return SSH_Message_Global_Request(
      requestName: 'cancel-tcpip-forward',
      wantReply: true,
      bindAddress: bindAddress,
      bindPort: bindPort,
    );
  }

  // /// Send additional host keys after authenticated.
  // factory SSH_Message_Global_Request.hostKeys({
  //   required List<SSHHostKey> hostKeys,
  // }) {
  //   return SSH_Message_Global_Request(
  //     requestName: 'hostkeys-00@openssh.com',
  //     wantReply: false,
  //     hostKeys: hostKeys,
  //   );
  // }

  factory SSH_Message_Global_Request.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final requestName = reader.readUtf8();
    final wantReply = reader.readBool();
    switch (requestName) {
      case 'tcpip-forward':
        final bindAddress = reader.readUtf8();
        final bindPort = reader.readUint32();
        return SSH_Message_Global_Request(
          requestName: requestName,
          wantReply: wantReply,
          bindAddress: bindAddress,
          bindPort: bindPort,
        );
      case 'cancel-tcpip-forward':
        final bindAddress = reader.readUtf8();
        final bindPort = reader.readUint32();
        return SSH_Message_Global_Request(
          requestName: requestName,
          wantReply: wantReply,
          bindAddress: bindAddress,
          bindPort: bindPort,
        );
      // case 'hostkeys-00@openssh.com':
      //   final hostKeys = reader.readStringList();
      //   return SSH_Message_Global_Request(
      //     requestName: requestName,
      //     wantReply: wantReply,
      //     hostKeys: _parseHostKeys(hostKeys),
      //   );
      default:
        return SSH_Message_Global_Request(
          requestName: requestName,
          wantReply: wantReply,
        );
    }
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeUtf8(requestName);
    writer.writeBool(wantReply);
    switch (requestName) {
      case 'tcpip-forward':
        writer.writeUtf8(bindAddress!);
        writer.writeUint32(bindPort!);
        break;
      case 'cancel-tcpip-forward':
        writer.writeUtf8(bindAddress!);
        writer.writeUint32(bindPort!);
        break;
      // case 'hostkeys-00@openssh.com':
      //   for (var hostkey in _encodeHostKeys(hostKeys!)) {
      //     writer.writeString(hostkey);
      //   }
      //   break;
    }
    return writer.takeBytes();
  }

  // static List<SSHHostKey> _parseHostKeys(List<Uint8List> pairs) {
  //   final result = <SSHHostKey>[];
  //   for (final pair in pairs) {
  //     final reader = SSHMessageReader(pair);
  //     final type = reader.readUtf8();
  //     final key = reader.readString();
  //     result.add(SSHHostKey(type, key));
  //   }
  //   return result;
  // }

  // static List<Uint8List> _encodeHostKeys(List<SSHHostKey> hostKeys) {
  //   final result = <Uint8List>[];
  //   for (final hostKey in hostKeys) {
  //     final writer = SSHMessageWriter();
  //     writer.writeUtf8(hostKey.type);
  //     writer.writeString(hostKey.key);
  //     result.add(writer.takeBytes());
  //   }
  //   return result;
  // }

  @override
  String toString() {
    switch (requestName) {
      case 'tcpip-forward':
        return 'SSH_Message_Global_Request(requestName: $requestName, wantReply: $wantReply, bindAddress: $bindAddress, bindPort: $bindPort)';
      case 'cancel-tcpip-forward':
        return 'SSH_Message_Global_Request(requestName: $requestName, wantReply: $wantReply, bindAddress: $bindAddress, bindPort: $bindPort)';
      // case 'hostkeys-00@openssh.com':
      //   return 'SSH_Message_Global_Request(requestName: $requestName, wantReply: $wantReply, hostKeys: $hostKeys)';
      default:
        return 'SSH_Message_Global_Request(requestName: $requestName, wantReply: $wantReply)';
    }
  }
}

class SSH_Message_Request_Success extends SSHMessage {
  static const messageId = 81;

  final Uint8List requestData;

  SSH_Message_Request_Success(this.requestData);

  factory SSH_Message_Request_Success.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final requestData = reader.readToEnd();
    return SSH_Message_Request_Success(requestData);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeBytes(requestData);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_Request_Success(requestData: ${hex.encode(requestData)})';
  }
}

/// Indicates that the recipient does not recognize or support the request.
class SSH_Message_Request_Failure extends SSHMessage {
  static const messageId = 82;

  SSH_Message_Request_Failure();

  factory SSH_Message_Request_Failure.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    return SSH_Message_Request_Failure();
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_Request_Failure()';
  }
}
