import 'dart:typed_data';

import 'package:dartssh2/src/message/base.dart';
import 'package:test/test.dart';

void main() {
  group('SSH_Message_Channel_Open', () {
    test('x11 encode/decode roundtrip', () {
      final message = SSH_Message_Channel_Open.x11(
        senderChannel: 7,
        initialWindowSize: 1024,
        maximumPacketSize: 32768,
        originatorIP: '127.0.0.1',
        originatorPort: 6123,
      );

      final decoded = SSH_Message_Channel_Open.decode(message.encode());

      expect(decoded.channelType, 'x11');
      expect(decoded.senderChannel, 7);
      expect(decoded.initialWindowSize, 1024);
      expect(decoded.maximumPacketSize, 32768);
      expect(decoded.originatorIP, '127.0.0.1');
      expect(decoded.originatorPort, 6123);
    });

    test('direct-streamlocal encode/decode roundtrip', () {
      final message = SSH_Message_Channel_Open.directStreamLocal(
        senderChannel: 11,
        initialWindowSize: 2048,
        maximumPacketSize: 32768,
        socketPath: '/var/run/docker.sock',
      );

      final decoded = SSH_Message_Channel_Open.decode(message.encode());

      expect(decoded.channelType, 'direct-streamlocal@openssh.com');
      expect(decoded.senderChannel, 11);
      expect(decoded.initialWindowSize, 2048);
      expect(decoded.maximumPacketSize, 32768);
      expect(decoded.socketPath, '/var/run/docker.sock');
    });

    test('direct-tcpip encode/decode roundtrip', () {
      final message = SSH_Message_Channel_Open.directTcpip(
        senderChannel: 9,
        initialWindowSize: 4096,
        maximumPacketSize: 32768,
        host: 'example.com',
        port: 443,
        originatorIP: '10.0.0.5',
        originatorPort: 5111,
      );

      final decoded = SSH_Message_Channel_Open.decode(message.encode());

      expect(decoded.channelType, 'direct-tcpip');
      expect(decoded.host, 'example.com');
      expect(decoded.port, 443);
      expect(decoded.originatorIP, '10.0.0.5');
      expect(decoded.originatorPort, 5111);
    });

    test('forwarded-tcpip encode/decode roundtrip', () {
      final message = SSH_Message_Channel_Open.forwardedTcpip(
        senderChannel: 10,
        initialWindowSize: 4096,
        maximumPacketSize: 32768,
        host: '127.0.0.1',
        port: 8080,
        originatorIP: '192.168.1.2',
        originatorPort: 1234,
      );

      final decoded = SSH_Message_Channel_Open.decode(message.encode());

      expect(decoded.channelType, 'forwarded-tcpip');
      expect(decoded.host, '127.0.0.1');
      expect(decoded.port, 8080);
      expect(decoded.originatorIP, '192.168.1.2');
      expect(decoded.originatorPort, 1234);
    });

    test('session encode/decode roundtrip', () {
      final message = SSH_Message_Channel_Open.session(
        senderChannel: 2,
        initialWindowSize: 2048,
        maximumPacketSize: 16384,
      );

      final decoded = SSH_Message_Channel_Open.decode(message.encode());

      expect(decoded.channelType, 'session');
      expect(decoded.senderChannel, 2);
      expect(decoded.initialWindowSize, 2048);
      expect(decoded.maximumPacketSize, 16384);
    });
  });

  group('SSH_Message_Channel_Generic', () {
    test('confirmation encode/decode roundtrip', () {
      final message = SSH_Message_Channel_Confirmation(
        recipientChannel: 1,
        senderChannel: 2,
        initialWindowSize: 1024,
        maximumPacketSize: 2048,
        data: Uint8List.fromList([4, 5, 6]),
      );

      final decoded = SSH_Message_Channel_Confirmation.decode(message.encode());

      expect(decoded.recipientChannel, 1);
      expect(decoded.senderChannel, 2);
      expect(decoded.initialWindowSize, 1024);
      expect(decoded.maximumPacketSize, 2048);
      expect(decoded.data, Uint8List.fromList([4, 5, 6]));
    });

    test('open failure encode/decode roundtrip', () {
      final message = SSH_Message_Channel_Open_Failure(
        recipientChannel: 3,
        reasonCode: SSH_Message_Channel_Open_Failure.codeConnectFailed,
        description: 'failed',
        languageTag: 'en',
      );

      final decoded = SSH_Message_Channel_Open_Failure.decode(message.encode());

      expect(decoded.recipientChannel, 3);
      expect(decoded.reasonCode,
          SSH_Message_Channel_Open_Failure.codeConnectFailed);
      expect(decoded.description, 'failed');
      expect(decoded.languageTag, 'en');
    });

    test('window adjust encode/decode roundtrip', () {
      final message = SSH_Message_Channel_Window_Adjust(
        recipientChannel: 7,
        bytesToAdd: 8192,
      );

      final decoded =
          SSH_Message_Channel_Window_Adjust.decode(message.encode());

      expect(decoded.recipientChannel, 7);
      expect(decoded.bytesToAdd, 8192);
    });

    test('data and extended data encode/decode roundtrip', () {
      final data = SSH_Message_Channel_Data(
        recipientChannel: 1,
        data: Uint8List.fromList([1, 2, 3]),
      );
      final dataDecoded = SSH_Message_Channel_Data.decode(data.encode());
      expect(dataDecoded.recipientChannel, 1);
      expect(dataDecoded.data, Uint8List.fromList([1, 2, 3]));

      final ext = SSH_Message_Channel_Extended_Data(
        recipientChannel: 1,
        dataTypeCode: SSH_Message_Channel_Extended_Data.dataTypeStderr,
        data: Uint8List.fromList([9, 8]),
      );
      final extDecoded = SSH_Message_Channel_Extended_Data.decode(ext.encode());
      expect(extDecoded.recipientChannel, 1);
      expect(extDecoded.dataTypeCode,
          SSH_Message_Channel_Extended_Data.dataTypeStderr);
      expect(extDecoded.data, Uint8List.fromList([9, 8]));
    });

    test('eof, close, success and failure encode/decode roundtrip', () {
      final eof = SSH_Message_Channel_EOF(recipientChannel: 9);
      final eofDecoded = SSH_Message_Channel_EOF.decode(eof.encode());
      expect(eofDecoded.recipientChannel, 9);

      final close = SSH_Message_Channel_Close(recipientChannel: 10);
      final closeDecoded = SSH_Message_Channel_Close.decode(close.encode());
      expect(closeDecoded.recipientChannel, 10);

      final success = SSH_Message_Channel_Success(recipientChannel: 11);
      final successDecoded =
          SSH_Message_Channel_Success.decode(success.encode());
      expect(successDecoded.recipientChannel, 11);

      final failure = SSH_Message_Channel_Failure(recipientChannel: 12);
      final failureDecoded =
          SSH_Message_Channel_Failure.decode(failure.encode());
      expect(failureDecoded.recipientChannel, 12);
    });
  });

  group('SSH_Message_Channel_Request', () {
    test('x11-req encode/decode roundtrip', () {
      final message = SSH_Message_Channel_Request.x11(
        recipientChannel: 5,
        wantReply: true,
        singleConnection: true,
        x11AuthenticationProtocol: 'MIT-MAGIC-COOKIE-1',
        x11AuthenticationCookie: 'deadbeef',
        x11ScreenNumber: '0',
      );

      final decoded = SSH_Message_Channel_Request.decode(message.encode());

      expect(decoded.requestType, SSHChannelRequestType.x11);
      expect(decoded.recipientChannel, 5);
      expect(decoded.wantReply, isTrue);
      expect(decoded.singleConnection, isTrue);
      expect(decoded.x11AuthenticationProtocol, 'MIT-MAGIC-COOKIE-1');
      expect(decoded.x11AuthenticationCookie, 'deadbeef');
      expect(decoded.x11ScreenNumber, '0');
    });

    test('auth-agent request encode/decode roundtrip', () {
      final message = SSH_Message_Channel_Request(
        recipientChannel: 3,
        requestType: SSHChannelRequestType.authAgent,
        wantReply: true,
      );

      final decoded = SSH_Message_Channel_Request.decode(message.encode());

      expect(decoded.requestType, SSHChannelRequestType.authAgent);
      expect(decoded.recipientChannel, 3);
      expect(decoded.wantReply, isTrue);
    });

    test('pty request encode/decode roundtrip', () {
      final message = SSH_Message_Channel_Request.pty(
        recipientChannel: 9,
        wantReply: true,
        termType: 'xterm-256color',
        termWidth: 120,
        termHeight: 40,
        termPixelWidth: 0,
        termPixelHeight: 0,
        termModes: Uint8List.fromList([0]),
      );

      final decoded = SSH_Message_Channel_Request.decode(message.encode());

      expect(decoded.requestType, SSHChannelRequestType.pty);
      expect(decoded.termType, 'xterm-256color');
      expect(decoded.termWidth, 120);
      expect(decoded.termHeight, 40);
    });

    test('env, exec and subsystem requests roundtrip', () {
      final env = SSH_Message_Channel_Request.env(
        recipientChannel: 1,
        wantReply: true,
        variableName: 'LANG',
        variableValue: 'en_US.UTF-8',
      );
      final envDecoded = SSH_Message_Channel_Request.decode(env.encode());
      expect(envDecoded.requestType, SSHChannelRequestType.env);
      expect(envDecoded.variableName, 'LANG');
      expect(envDecoded.variableValue, 'en_US.UTF-8');

      final exec = SSH_Message_Channel_Request.exec(
        recipientChannel: 1,
        wantReply: true,
        command: 'ls -la',
      );
      final execDecoded = SSH_Message_Channel_Request.decode(exec.encode());
      expect(execDecoded.requestType, SSHChannelRequestType.exec);
      expect(execDecoded.command, 'ls -la');

      final subsystem = SSH_Message_Channel_Request.subsystem(
        recipientChannel: 1,
        wantReply: true,
        subsystemName: 'sftp',
      );
      final subsystemDecoded =
          SSH_Message_Channel_Request.decode(subsystem.encode());
      expect(subsystemDecoded.requestType, SSHChannelRequestType.subsystem);
      expect(subsystemDecoded.subsystemName, 'sftp');
    });

    test('window-change, signal and exit-status requests roundtrip', () {
      final windowChange = SSH_Message_Channel_Request.windowChange(
        recipientChannel: 2,
        termWidth: 100,
        termHeight: 30,
        termPixelWidth: 800,
        termPixelHeight: 600,
      );
      final windowDecoded =
          SSH_Message_Channel_Request.decode(windowChange.encode());
      expect(windowDecoded.requestType, SSHChannelRequestType.windowChange);
      expect(windowDecoded.termWidth, 100);
      expect(windowDecoded.termHeight, 30);
      expect(windowDecoded.termPixelWidth, 800);
      expect(windowDecoded.termPixelHeight, 600);

      final signal = SSH_Message_Channel_Request.signal(
        recipientChannel: 2,
        signalName: 'KILL',
      );
      final signalDecoded = SSH_Message_Channel_Request.decode(signal.encode());
      expect(signalDecoded.requestType, SSHChannelRequestType.signal);
      expect(signalDecoded.signalName, 'KILL');

      final exitStatus = SSH_Message_Channel_Request.exitStatus(
        recipientChannel: 2,
        exitStatus: 127,
      );
      final exitStatusDecoded =
          SSH_Message_Channel_Request.decode(exitStatus.encode());
      expect(exitStatusDecoded.requestType, SSHChannelRequestType.exitStatus);
      expect(exitStatusDecoded.exitStatus, 127);
    });

    test('exit-signal request encode/decode roundtrip', () {
      final message = SSH_Message_Channel_Request.exitSignal(
        recipientChannel: 6,
        exitSignalName: 'TERM',
        coreDumped: true,
        errorMessage: 'terminated',
        languageTag: 'en',
      );

      final decoded = SSH_Message_Channel_Request.decode(message.encode());

      expect(decoded.requestType, SSHChannelRequestType.exitSignal);
      expect(decoded.exitSignalName, 'TERM');
      expect(decoded.coreDumped, isTrue);
      expect(decoded.errorMessage, 'terminated');
      expect(decoded.languageTag, 'en');
    });

    test('unknown request type decodes as generic request', () {
      final writer = SSHMessageWriter();
      writer.writeUint8(SSH_Message_Channel_Request.messageId);
      writer.writeUint32(13);
      writer.writeUtf8('custom-request');
      writer.writeBool(false);

      final decoded = SSH_Message_Channel_Request.decode(writer.takeBytes());

      expect(decoded.recipientChannel, 13);
      expect(decoded.requestType, 'custom-request');
      expect(decoded.wantReply, isFalse);
    });
  });
}
