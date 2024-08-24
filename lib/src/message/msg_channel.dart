// ignore_for_file: camel_case_types

import 'dart:typed_data';

import 'package:dartssh4/src/ssh_message.dart';

/// Message to request opening a channel to remote host.
class SSH_Message_Channel_Open implements SSHMessage {
  static const messageId = 90;

  /// `session`, `x11`, `direct-tcpip` or `forwarded-tcpip`
  final String channelType;

  /// The channel number.
  final int senderChannel;

  final int initialWindowSize;

  final int maximumPacketSize;

  /// "forwarded-tcpip" "direct-tcpip" "x11" channel specific data.
  final String? host;
  final int? port;
  final String? originatorIP;
  final int? originatorPort;

  SSH_Message_Channel_Open({
    required this.channelType,
    required this.senderChannel,
    required this.initialWindowSize,
    required this.maximumPacketSize,
    this.host,
    this.port,
    this.originatorIP,
    this.originatorPort,
  });

  factory SSH_Message_Channel_Open.session({
    required int senderChannel,
    required int initialWindowSize,
    required int maximumPacketSize,
  }) {
    return SSH_Message_Channel_Open(
      channelType: 'session',
      senderChannel: senderChannel,
      initialWindowSize: initialWindowSize,
      maximumPacketSize: maximumPacketSize,
    );
  }

  factory SSH_Message_Channel_Open.x11({
    required int senderChannel,
    required int initialWindowSize,
    required int maximumPacketSize,
    required String originatorIP,
    required int originatorPort,
  }) {
    return SSH_Message_Channel_Open(
      channelType: 'x11',
      senderChannel: senderChannel,
      initialWindowSize: initialWindowSize,
      maximumPacketSize: maximumPacketSize,
      originatorIP: originatorIP,
      originatorPort: originatorPort,
    );
  }

  factory SSH_Message_Channel_Open.forwardedTcpip({
    required int senderChannel,
    required int initialWindowSize,
    required int maximumPacketSize,
    required String host,
    required int port,
    required String originatorIP,
    required int originatorPort,
  }) {
    return SSH_Message_Channel_Open(
      channelType: 'forwarded-tcpip',
      senderChannel: senderChannel,
      initialWindowSize: initialWindowSize,
      maximumPacketSize: maximumPacketSize,
      host: host,
      port: port,
      originatorIP: originatorIP,
      originatorPort: originatorPort,
    );
  }

  factory SSH_Message_Channel_Open.directTcpip({
    required int senderChannel,
    required int initialWindowSize,
    required int maximumPacketSize,
    required String host,
    required int port,
    required String originatorIP,
    required int originatorPort,
  }) {
    return SSH_Message_Channel_Open(
      channelType: 'direct-tcpip',
      senderChannel: senderChannel,
      initialWindowSize: initialWindowSize,
      maximumPacketSize: maximumPacketSize,
      host: host,
      port: port,
      originatorIP: originatorIP,
      originatorPort: originatorPort,
    );
  }

  factory SSH_Message_Channel_Open.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final channelType = reader.readUtf8();
    final senderChannel = reader.readUint32();
    final initialWindowSize = reader.readUint32();
    final maximumPacketSize = reader.readUint32();
    switch (channelType) {
      case 'session':
        return SSH_Message_Channel_Open.session(
          senderChannel: senderChannel,
          initialWindowSize: initialWindowSize,
          maximumPacketSize: maximumPacketSize,
        );
      case 'x11':
        final originatorIP = reader.readUtf8();
        final originatorPort = reader.readUint32();
        return SSH_Message_Channel_Open.x11(
          senderChannel: senderChannel,
          initialWindowSize: initialWindowSize,
          maximumPacketSize: maximumPacketSize,
          originatorIP: originatorIP,
          originatorPort: originatorPort,
        );
      case 'forwarded-tcpip':
        final host = reader.readUtf8();
        final port = reader.readUint32();
        final originatorIP = reader.readUtf8();
        final originatorPort = reader.readUint32();
        return SSH_Message_Channel_Open.forwardedTcpip(
          senderChannel: senderChannel,
          initialWindowSize: initialWindowSize,
          maximumPacketSize: maximumPacketSize,
          host: host,
          port: port,
          originatorIP: originatorIP,
          originatorPort: originatorPort,
        );
      case 'direct-tcpip':
        final host = reader.readUtf8();
        final port = reader.readUint32();
        final originatorIP = reader.readUtf8();
        final originatorPort = reader.readUint32();
        return SSH_Message_Channel_Open.directTcpip(
          senderChannel: senderChannel,
          initialWindowSize: initialWindowSize,
          maximumPacketSize: maximumPacketSize,
          host: host,
          port: port,
          originatorIP: originatorIP,
          originatorPort: originatorPort,
        );

      default:
        return SSH_Message_Channel_Open(
          channelType: channelType,
          senderChannel: senderChannel,
          initialWindowSize: initialWindowSize,
          maximumPacketSize: maximumPacketSize,
        );
    }
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeUtf8(channelType);
    writer.writeUint32(senderChannel);
    writer.writeUint32(initialWindowSize);
    writer.writeUint32(maximumPacketSize);
    switch (channelType) {
      case 'session':
        break;
      case 'x11':
        writer.writeUtf8(originatorIP!);
        writer.writeUint32(originatorPort!);
        break;
      case 'forwarded-tcpip':
        writer.writeUtf8(host!);
        writer.writeUint32(port!);
        writer.writeUtf8(originatorIP!);
        writer.writeUint32(originatorPort!);
        break;
      case 'direct-tcpip':
        writer.writeUtf8(host!);
        writer.writeUint32(port!);
        writer.writeUtf8(originatorIP!);
        writer.writeUint32(originatorPort!);
        break;
    }
    return writer.takeBytes();
  }

  @override
  String toString() {
    switch (channelType) {
      case 'session':
        return 'SSH_Message_Channel_Open(channelType: $channelType, senderChannel: $senderChannel, initialWindowSize: $initialWindowSize, maximumPacketSize: $maximumPacketSize)';
      case 'x11':
        return 'SSH_Message_Channel_Open(channelType: $channelType, senderChannel: $senderChannel, initialWindowSize: $initialWindowSize, maximumPacketSize: $maximumPacketSize, originatorIP: $originatorIP, originatorPort: $originatorPort)';
      case 'forwarded-tcpip':
        return 'SSH_Message_Channel_Open(channelType: $channelType, senderChannel: $senderChannel, initialWindowSize: $initialWindowSize, maximumPacketSize: $maximumPacketSize, host: $host, port: $port, originatorIP: $originatorIP, originatorPort: $originatorPort)';
      case 'direct-tcpip':
        return 'SSH_Message_Channel_Open(channelType: $channelType, senderChannel: $senderChannel, initialWindowSize: $initialWindowSize, maximumPacketSize: $maximumPacketSize, host: $host, port: $port, originatorIP: $originatorIP, originatorPort: $originatorPort)';
      default:
        return 'SSH_Message_Channel_Open(channelType: $channelType, senderChannel: $senderChannel, initialWindowSize: $initialWindowSize, maximumPacketSize: $maximumPacketSize)';
    }
  }
}

/// Message to inform remote host that channel is open.
class SSH_Message_Channel_Confirmation implements SSHMessage {
  static const messageId = 91;

  /// The channel number given in the original open request
  final int recipientChannel;

  /// The channel number allocated by the other side.
  final int senderChannel;

  final int initialWindowSize;

  final int maximumPacketSize;

  final Uint8List data;

  SSH_Message_Channel_Confirmation({
    required this.recipientChannel,
    required this.senderChannel,
    required this.initialWindowSize,
    required this.maximumPacketSize,
    required this.data,
  });

  factory SSH_Message_Channel_Confirmation.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final recipientChannel = reader.readUint32();
    final senderChannel = reader.readUint32();
    final initialWindowSize = reader.readUint32();
    final maximumPacketSize = reader.readUint32();
    final data = reader.readToEnd();
    return SSH_Message_Channel_Confirmation(
      recipientChannel: recipientChannel,
      senderChannel: senderChannel,
      initialWindowSize: initialWindowSize,
      maximumPacketSize: maximumPacketSize,
      data: data,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeUint32(recipientChannel);
    writer.writeUint32(senderChannel);
    writer.writeUint32(initialWindowSize);
    writer.writeUint32(maximumPacketSize);
    writer.writeBytes(data);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_Channel_Confirmation(recipientChannel: $recipientChannel, senderChannel: $senderChannel, initialWindowSize: $initialWindowSize, maximumPacketSize: $maximumPacketSize)';
  }
}

/// Message to inform remote host that channel can't be opened.
class SSH_Message_Channel_Open_Failure implements SSHMessage {
  static const messageId = 92;

  // Reason codes for failure
  static const codeAdministrativelyProhibited = 1;
  static const codeConnectFailed = 2;
  static const codeUnknownChannelType = 3;
  static const codeResourceShortage = 4;

  /// The channel number given in the original open request
  final int recipientChannel;

  final int reasonCode;

  final String description;

  final String languageTag;

  SSH_Message_Channel_Open_Failure({
    required this.recipientChannel,
    required this.reasonCode,
    required this.description,
    this.languageTag = '',
  });

  factory SSH_Message_Channel_Open_Failure.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final recipientChannel = reader.readUint32();
    final reasonCode = reader.readUint32();
    final description = reader.readUtf8();
    final languageTag = reader.readUtf8();
    return SSH_Message_Channel_Open_Failure(
      recipientChannel: recipientChannel,
      reasonCode: reasonCode,
      description: description,
      languageTag: languageTag,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeUint32(recipientChannel);
    writer.writeUint32(reasonCode);
    writer.writeUtf8(description);
    writer.writeUtf8(languageTag);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_Channel_Open_Failure(recipientChannel: $recipientChannel, reasonCode: $reasonCode, description: $description, languageTag: $languageTag)';
  }
}

/// Message to inform remote host how many bytes can be sent before it must wait
/// for window to be increased.
class SSH_Message_Channel_Window_Adjust implements SSHMessage {
  static const messageId = 93;

  /// The channel number given in the original open request
  final int recipientChannel;

  final int bytesToAdd;

  SSH_Message_Channel_Window_Adjust({
    required this.recipientChannel,
    required this.bytesToAdd,
  });

  factory SSH_Message_Channel_Window_Adjust.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final recipientChannel = reader.readUint32();
    final bytesToAdd = reader.readUint32();
    return SSH_Message_Channel_Window_Adjust(
      recipientChannel: recipientChannel,
      bytesToAdd: bytesToAdd,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeUint32(recipientChannel);
    writer.writeUint32(bytesToAdd);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_Channel_Window_Adjust(recipientChannel: $recipientChannel, bytesToAdd: $bytesToAdd)';
  }
}

/// Message to transfer data between channels.
class SSH_Message_Channel_Data implements SSHMessage {
  static const messageId = 94;

  /// The channel number
  final int recipientChannel;

  /// The data to send
  final Uint8List data;

  SSH_Message_Channel_Data({
    required this.recipientChannel,
    required this.data,
  });

  factory SSH_Message_Channel_Data.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final recipientChannel = reader.readUint32();
    final data = reader.readString();
    return SSH_Message_Channel_Data(
      recipientChannel: recipientChannel,
      data: data,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeUint32(recipientChannel);
    writer.writeString(data);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_Channel_Data(recipientChannel: $recipientChannel, data.length=${data.length})';
  }
}

class SSH_Message_Channel_Extended_Data implements SSHMessage {
  static const messageId = 95;

  static const dataTypeStderr = 1;

  /// The channel number
  final int recipientChannel;

  /// The data to send
  final int dataTypeCode;

  /// The data to send
  final Uint8List data;

  SSH_Message_Channel_Extended_Data({
    required this.recipientChannel,
    required this.dataTypeCode,
    required this.data,
  });

  factory SSH_Message_Channel_Extended_Data.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final recipientChannel = reader.readUint32();
    final dataTypeCode = reader.readUint32();
    final data = reader.readString();
    return SSH_Message_Channel_Extended_Data(
      recipientChannel: recipientChannel,
      dataTypeCode: dataTypeCode,
      data: data,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeUint32(recipientChannel);
    writer.writeUint32(dataTypeCode);
    writer.writeString(data);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_Channel_Extended_Data(recipientChannel: $recipientChannel, dataTypeCode: $dataTypeCode, data.length=${data.length})';
  }
}

/// Message to inform remote host that no more data will be sent.
class SSH_Message_Channel_EOF implements SSHMessage {
  static const messageId = 96;

  /// The channel number
  final int recipientChannel;

  SSH_Message_Channel_EOF({
    required this.recipientChannel,
  });

  factory SSH_Message_Channel_EOF.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final recipientChannel = reader.readUint32();
    return SSH_Message_Channel_EOF(
      recipientChannel: recipientChannel,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeUint32(recipientChannel);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_Channel_EOF(recipientChannel: $recipientChannel)';
  }
}

/// Message to inform remote host the channel is now closed.
class SSH_Message_Channel_Close implements SSHMessage {
  static const messageId = 97;

  /// The channel number
  final int recipientChannel;

  SSH_Message_Channel_Close({
    required this.recipientChannel,
  });

  factory SSH_Message_Channel_Close.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final recipientChannel = reader.readUint32();
    return SSH_Message_Channel_Close(
      recipientChannel: recipientChannel,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeUint32(recipientChannel);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_Channel_Close(recipientChannel: $recipientChannel)';
  }
}

abstract class SSHChannelRequestType {
  static const pty = 'pty-req';
  static const x11 = 'x11-req';
  static const env = 'env';
  static const shell = 'shell';
  static const exec = 'exec';
  static const subsystem = 'subsystem';
  static const windowChange = 'window-change';
  static const xon = 'xon-xoff';
  static const signal = 'signal';
  static const exitStatus = 'exit-status';
  static const exitSignal = 'exit-signal';
}

/// Message to send channel-specific requests.
class SSH_Message_Channel_Request implements SSHMessage {
  static const messageId = 98;

  final int recipientChannel;
  final String requestType;
  final bool wantReply;

  /// "pty-req" and "window-change" request specific data
  final String? termType;
  final int? termWidth;
  final int? termHeight;
  final int? termPixelWidth;
  final int? termPixelHeight;
  final Uint8List? termModes;

  /// "x11-req" request specific data
  final bool? singleConnection;
  final String? x11AuthenticationProtocol;
  final String? x11AuthenticationCookie;
  final String? x11ScreenNumber;

  /// "env" request specific data
  final String? variableName;
  final String? variableValue;

  /// "exec" request specific data
  final String? command;

  /// "subsystem" request specific data
  final String? subsystemName;

  /// "signal" request specific data, signal name (without the "SIG" prefix)
  final String? signalName;

  /// "exit-status" request specific data
  final int? exitStatus;

  /// "exit-signal" request specific data
  final String? exitSignalName;
  final bool? coreDumped;
  final String? errorMessage;
  final String? languageTag;

  SSH_Message_Channel_Request({
    required this.recipientChannel,
    required this.requestType,
    required this.wantReply,
    this.termType,
    this.termWidth,
    this.termHeight,
    this.termPixelWidth,
    this.termPixelHeight,
    this.termModes,
    this.singleConnection,
    this.x11AuthenticationProtocol,
    this.x11AuthenticationCookie,
    this.x11ScreenNumber,
    this.variableName,
    this.variableValue,
    this.command,
    this.subsystemName,
    this.signalName,
    this.exitStatus,
    this.exitSignalName,
    this.coreDumped,
    this.errorMessage,
    this.languageTag,
  });

  /// Request a pseudo-terminal to be allocated for the session
  factory SSH_Message_Channel_Request.pty({
    required int recipientChannel,
    bool wantReply = false,
    required String termType,
    required int termWidth,
    required int termHeight,
    required int termPixelWidth,
    required int termPixelHeight,
    required Uint8List termModes,
  }) {
    return SSH_Message_Channel_Request(
      recipientChannel: recipientChannel,
      requestType: SSHChannelRequestType.pty,
      wantReply: wantReply,
      termType: termType,
      termWidth: termWidth,
      termHeight: termHeight,
      termPixelWidth: termPixelWidth,
      termPixelHeight: termPixelHeight,
      termModes: termModes,
    );
  }

  /// Request x11 forwarding for the session
  factory SSH_Message_Channel_Request.x11({
    required int recipientChannel,
    bool wantReply = false,
    bool singleConnection = false,
    required String x11AuthenticationProtocol,
    required String x11AuthenticationCookie,
    required String x11ScreenNumber,
  }) {
    return SSH_Message_Channel_Request(
      recipientChannel: recipientChannel,
      requestType: SSHChannelRequestType.x11,
      wantReply: wantReply,
      singleConnection: singleConnection,
      x11AuthenticationProtocol: x11AuthenticationProtocol,
      x11AuthenticationCookie: x11AuthenticationCookie,
      x11ScreenNumber: x11ScreenNumber,
    );
  }

  /// Pass environment variable to the shell/command to be started later
  factory SSH_Message_Channel_Request.env({
    required int recipientChannel,
    bool wantReply = false,
    required String variableName,
    required String variableValue,
  }) {
    return SSH_Message_Channel_Request(
      recipientChannel: recipientChannel,
      requestType: SSHChannelRequestType.env,
      wantReply: wantReply,
      variableName: variableName,
      variableValue: variableValue,
    );
  }

  /// Request that the user's default shell be started at the other end
  factory SSH_Message_Channel_Request.shell({
    required int recipientChannel,
    required bool wantReply,
  }) {
    return SSH_Message_Channel_Request(
      recipientChannel: recipientChannel,
      requestType: SSHChannelRequestType.shell,
      wantReply: wantReply,
    );
  }

  /// Request the server start executing the given command
  factory SSH_Message_Channel_Request.exec({
    required int recipientChannel,
    required bool wantReply,
    required String command,
  }) {
    return SSH_Message_Channel_Request(
      recipientChannel: recipientChannel,
      requestType: SSHChannelRequestType.exec,
      wantReply: wantReply,
      command: command,
    );
  }

  /// Request the server execute a predefined subsystem
  factory SSH_Message_Channel_Request.subsystem({
    required int recipientChannel,
    required bool wantReply,
    required String subsystemName,
  }) {
    return SSH_Message_Channel_Request(
      recipientChannel: recipientChannel,
      requestType: SSHChannelRequestType.subsystem,
      wantReply: wantReply,
      subsystemName: subsystemName,
    );
  }

  /// Inform the server that the window size has changed
  factory SSH_Message_Channel_Request.windowChange({
    required int recipientChannel,
    required int termWidth,
    required int termHeight,
    required int termPixelWidth,
    required int termPixelHeight,
  }) {
    return SSH_Message_Channel_Request(
      recipientChannel: recipientChannel,
      requestType: SSHChannelRequestType.windowChange,
      wantReply: false,
      termWidth: termWidth,
      termHeight: termHeight,
      termPixelWidth: termPixelWidth,
      termPixelHeight: termPixelHeight,
    );
  }

  /// Deliver a signal to the process on the other end of the channel
  factory SSH_Message_Channel_Request.signal({
    required int recipientChannel,
    required String signalName,
  }) {
    return SSH_Message_Channel_Request(
      recipientChannel: recipientChannel,
      requestType: SSHChannelRequestType.signal,
      wantReply: false,
      signalName: signalName,
    );
  }

  /// Return exit status of the process on the other end of the channel
  factory SSH_Message_Channel_Request.exitStatus({
    required int recipientChannel,
    required int exitStatus,
  }) {
    return SSH_Message_Channel_Request(
      recipientChannel: recipientChannel,
      requestType: SSHChannelRequestType.exitStatus,
      wantReply: false,
      exitStatus: exitStatus,
    );
  }

  /// Indicate that the remote command terminated due to a signal
  factory SSH_Message_Channel_Request.exitSignal({
    required int recipientChannel,
    required String exitSignalName,
    bool coreDumped = false,
    String? errorMessage,
    String? languageTag,
  }) {
    return SSH_Message_Channel_Request(
      recipientChannel: recipientChannel,
      requestType: SSHChannelRequestType.exitSignal,
      wantReply: false,
      exitSignalName: exitSignalName,
      coreDumped: coreDumped,
      errorMessage: errorMessage,
      languageTag: languageTag,
    );
  }

  factory SSH_Message_Channel_Request.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final recipientChannel = reader.readUint32();
    final requestType = reader.readUtf8();
    final wantReply = reader.readBool();
    switch (requestType) {
      case SSHChannelRequestType.pty:
        final termType = reader.readUtf8();
        final termWidth = reader.readUint32();
        final termHeight = reader.readUint32();
        final termPixelWidth = reader.readUint32();
        final termPixelHeight = reader.readUint32();
        final termModes = reader.readString();
        return SSH_Message_Channel_Request(
          recipientChannel: recipientChannel,
          requestType: requestType,
          wantReply: wantReply,
          termType: termType,
          termWidth: termWidth,
          termHeight: termHeight,
          termPixelWidth: termPixelWidth,
          termPixelHeight: termPixelHeight,
          termModes: termModes,
        );
      case SSHChannelRequestType.x11:
        final singleConnection = reader.readBool();
        final x11AuthenticationProtocol = reader.readUtf8();
        final x11AuthenticationCookie = reader.readUtf8();
        final x11ScreenNumber = reader.readUtf8();
        return SSH_Message_Channel_Request(
          recipientChannel: recipientChannel,
          requestType: requestType,
          wantReply: wantReply,
          singleConnection: singleConnection,
          x11AuthenticationProtocol: x11AuthenticationProtocol,
          x11AuthenticationCookie: x11AuthenticationCookie,
          x11ScreenNumber: x11ScreenNumber,
        );
      case SSHChannelRequestType.env:
        final variableName = reader.readUtf8();
        final variableValue = reader.readUtf8();
        return SSH_Message_Channel_Request(
          recipientChannel: recipientChannel,
          requestType: requestType,
          wantReply: wantReply,
          variableName: variableName,
          variableValue: variableValue,
        );
      case SSHChannelRequestType.shell:
        return SSH_Message_Channel_Request.shell(
          recipientChannel: recipientChannel,
          wantReply: wantReply,
        );
      case SSHChannelRequestType.exec:
        final command = reader.readUtf8();
        return SSH_Message_Channel_Request.exec(
          recipientChannel: recipientChannel,
          wantReply: wantReply,
          command: command,
        );
      case SSHChannelRequestType.subsystem:
        final subsystemName = reader.readUtf8();
        return SSH_Message_Channel_Request.subsystem(
          recipientChannel: recipientChannel,
          wantReply: wantReply,
          subsystemName: subsystemName,
        );
      case SSHChannelRequestType.windowChange:
        final termWidth = reader.readUint32();
        final termHeight = reader.readUint32();
        final termPixelWidth = reader.readUint32();
        final termPixelHeight = reader.readUint32();
        return SSH_Message_Channel_Request.windowChange(
          recipientChannel: recipientChannel,
          termWidth: termWidth,
          termHeight: termHeight,
          termPixelWidth: termPixelWidth,
          termPixelHeight: termPixelHeight,
        );
      case SSHChannelRequestType.signal:
        final signalName = reader.readUtf8();
        return SSH_Message_Channel_Request.signal(
          recipientChannel: recipientChannel,
          signalName: signalName,
        );
      case SSHChannelRequestType.exitStatus:
        final exitStatus = reader.readUint32();
        return SSH_Message_Channel_Request.exitStatus(
          recipientChannel: recipientChannel,
          exitStatus: exitStatus,
        );
      case SSHChannelRequestType.exitSignal:
        final exitSignalName = reader.readUtf8();
        final coreDumped = reader.readBool();
        final errorMessage = reader.readUtf8();
        final languageTag = reader.readUtf8();
        return SSH_Message_Channel_Request.exitSignal(
          recipientChannel: recipientChannel,
          exitSignalName: exitSignalName,
          coreDumped: coreDumped,
          errorMessage: errorMessage,
          languageTag: languageTag,
        );
      default:
        return SSH_Message_Channel_Request(
          recipientChannel: recipientChannel,
          requestType: requestType,
          wantReply: wantReply,
        );
    }
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeUint32(recipientChannel);
    writer.writeUtf8(requestType);
    writer.writeBool(wantReply);
    switch (requestType) {
      case 'pty-req':
        writer.writeUtf8(termType!);
        writer.writeUint32(termWidth!);
        writer.writeUint32(termHeight!);
        writer.writeUint32(termPixelWidth!);
        writer.writeUint32(termPixelHeight!);
        writer.writeString(termModes!);
        break;
      case 'x11-req':
        writer.writeBool(singleConnection!);
        writer.writeUtf8(x11AuthenticationProtocol!);
        writer.writeUtf8(x11AuthenticationCookie!);
        writer.writeUtf8(x11ScreenNumber!);
        break;
      case 'env':
        writer.writeUtf8(variableName!);
        writer.writeUtf8(variableValue!);
        break;
      case 'shell':
        break;
      case 'exec':
        writer.writeUtf8(command!);
        break;
      case 'subsystem':
        writer.writeUtf8(subsystemName!);
        break;
      case 'window-change':
        writer.writeUint32(termWidth!);
        writer.writeUint32(termHeight!);
        writer.writeUint32(termPixelWidth!);
        writer.writeUint32(termPixelHeight!);
        break;
      case 'signal':
        writer.writeUtf8(signalName!);
        break;
      case 'exit-status':
        writer.writeUint32(exitStatus!);
        break;
      case 'exit-signal':
        writer.writeUtf8(exitSignalName!);
        writer.writeBool(coreDumped!);
        writer.writeUtf8(errorMessage!);
        writer.writeUtf8(languageTag!);
        break;
    }
    return writer.takeBytes();
  }

  @override
  String toString() {
    switch (requestType) {
      case 'pty-req':
        return 'SSH_Message_Channel_Request(recipientChannel: $recipientChannel, requestType: $requestType, wantReply: $wantReply, termType: $termType, termWidth: $termWidth, termHeight: $termHeight, termPixelWidth: $termPixelWidth, termPixelHeight: $termPixelHeight, termModes: $termModes)';
      case 'x11-req':
        return 'SSH_Message_Channel_Request(recipientChannel: $recipientChannel, requestType: $requestType, wantReply: $wantReply, singleConnection: $singleConnection, x11AuthenticationProtocol: $x11AuthenticationProtocol, x11AuthenticationCookie: $x11AuthenticationCookie, x11ScreenNumber: $x11ScreenNumber)';
      case 'env':
        return 'SSH_Message_Channel_Request(recipientChannel: $recipientChannel, requestType: $requestType, wantReply: $wantReply, variableName: $variableName, variableValue: $variableValue)';
      case 'shell':
        return 'SSH_Message_Channel_Request(recipientChannel: $recipientChannel, requestType: $requestType, wantReply: $wantReply)';
      case 'exec':
        return 'SSH_Message_Channel_Request(recipientChannel: $recipientChannel, requestType: $requestType, wantReply: $wantReply, command: $command)';
      case 'subsystem':
        return 'SSH_Message_Channel_Request(recipientChannel: $recipientChannel, requestType: $requestType, wantReply: $wantReply, subsystemName: $subsystemName)';
      case 'window-change':
        return 'SSH_Message_Channel_Request(recipientChannel: $recipientChannel, requestType: $requestType, wantReply: $wantReply, termWidth: $termWidth, termHeight: $termHeight, termPixelWidth: $termPixelWidth, termPixelHeight: $termPixelHeight)';
      case 'signal':
        return 'SSH_Message_Channel_Request(recipientChannel: $recipientChannel, requestType: $requestType, wantReply: $wantReply, signalName: $signalName)';
      case 'exit-status':
        return 'SSH_Message_Channel_Request(recipientChannel: $recipientChannel, requestType: $requestType, wantReply: $wantReply, exitStatus: $exitStatus)';
      case 'exit-signal':
        return 'SSH_Message_Channel_Request(recipientChannel: $recipientChannel, requestType: $requestType, wantReply: $wantReply, exitSignalName: $exitSignalName, coreDumped: $coreDumped, errorMessage: $errorMessage, languageTag: $languageTag)';
      default:
        return 'SSH_Message_Channel_Request(recipientChannel: $recipientChannel, requestType: $requestType, wantReply: $wantReply)';
    }
  }
}

/// Response to a [SSH_Message_Channel_Request] if the request was successful
class SSH_Message_Channel_Success extends SSHMessage {
  static const int messageId = 99;

  /// The channel number the request was sent on
  final int recipientChannel;

  SSH_Message_Channel_Success({
    required this.recipientChannel,
  });

  factory SSH_Message_Channel_Success.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final recipientChannel = reader.readUint32();
    return SSH_Message_Channel_Success(
      recipientChannel: recipientChannel,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeUint32(recipientChannel);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_Channel_Success(recipientChannel: $recipientChannel)';
  }
}

/// Response to a [SSH_Message_Channel_Request] if the request failed
class SSH_Message_Channel_Failure extends SSHMessage {
  static const int messageId = 100;

  /// The channel number the request was sent on
  final int recipientChannel;

  SSH_Message_Channel_Failure({
    required this.recipientChannel,
  });

  factory SSH_Message_Channel_Failure.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final recipientChannel = reader.readUint32();
    return SSH_Message_Channel_Failure(
      recipientChannel: recipientChannel,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeUint32(recipientChannel);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_Channel_Failure(recipientChannel: $recipientChannel)';
  }
}
