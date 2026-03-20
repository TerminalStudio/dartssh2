import 'package:dartssh2/src/message/msg_channel.dart';
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
  });
}
