import 'dart:typed_data';

import 'package:dartssh2/src/message/msg_channel.dart';
import 'package:dartssh2/src/ssh_channel.dart';
import 'package:dartssh2/src/ssh_errors.dart';
import 'package:dartssh2/src/ssh_message.dart';
import 'package:test/test.dart';

void main() {
  group('SSHChannelController', () {
    test('exposes distinct local and remote channel IDs', () {
      final controller = _createController();

      final channel = controller.channel;

      expect(channel.channelId, 1);
      expect(channel.remoteChannelId, 42);
    });

    test('adjusts the local window when it is exactly exhausted', () async {
      final sent = <SSHMessage>[];
      final controller = _createController(
        localInitialWindowSize: 4,
        localMaximumPacketSize: 4,
        sendMessage: sent.add,
      );
      final subscription = controller.channel.stream.listen((_) {});

      controller.handleMessage(
        SSH_Message_Channel_Data(
          recipientChannel: 1,
          data: Uint8List(4),
        ),
      );

      final adjustment = sent.single as SSH_Message_Channel_Window_Adjust;
      expect(adjustment.recipientChannel, 42);
      expect(adjustment.bytesToAdd, 4);
      await subscription.cancel();
    });

    test('allows the remote window to reach uint32 max without wrapping', () {
      final controller = _createController(remoteInitialWindowSize: 0);

      controller.handleMessage(
        SSH_Message_Channel_Window_Adjust(
          recipientChannel: 1,
          bytesToAdd: 0xffffffff,
        ),
      );

      expect(
        () => controller.handleMessage(
          SSH_Message_Channel_Window_Adjust(
            recipientChannel: 1,
            bytesToAdd: 1,
          ),
        ),
        throwsA(isA<SSHStateError>()),
      );
    });

    test('rejects data larger than the advertised maximum packet size', () {
      final sent = <SSHMessage>[];
      final controller = _createController(
        localInitialWindowSize: 8,
        localMaximumPacketSize: 4,
        sendMessage: sent.add,
      );

      expect(
        () => controller.handleMessage(
          SSH_Message_Channel_Data(
            recipientChannel: 1,
            data: Uint8List(5),
          ),
        ),
        throwsA(isA<SSHStateError>()),
      );
      expect(sent, isEmpty);
    });

    test('rejects data larger than the remaining local window', () {
      final sent = <SSHMessage>[];
      final controller = _createController(
        localInitialWindowSize: 4,
        localMaximumPacketSize: 8,
        sendMessage: sent.add,
      );

      expect(
        () => controller.handleMessage(
          SSH_Message_Channel_Data(
            recipientChannel: 1,
            data: Uint8List(5),
          ),
        ),
        throwsA(isA<SSHStateError>()),
      );
      expect(sent, isEmpty);
    });

    test('applies packet and window limits to extended data', () async {
      final sent = <SSHMessage>[];
      final controller = _createController(
        localInitialWindowSize: 4,
        localMaximumPacketSize: 4,
        sendMessage: sent.add,
      );
      final subscription = controller.channel.stream.listen((_) {});

      controller.handleMessage(
        SSH_Message_Channel_Extended_Data(
          recipientChannel: 1,
          dataTypeCode: SSH_Message_Channel_Extended_Data.dataTypeStderr,
          data: Uint8List(4),
        ),
      );

      final adjustment = sent.single as SSH_Message_Channel_Window_Adjust;
      expect(adjustment.bytesToAdd, 4);

      expect(
        () => controller.handleMessage(
          SSH_Message_Channel_Extended_Data(
            recipientChannel: 1,
            dataTypeCode: SSH_Message_Channel_Extended_Data.dataTypeStderr,
            data: Uint8List(5),
          ),
        ),
        throwsA(isA<SSHStateError>()),
      );
      expect(sent, hasLength(1));

      final windowController = _createController(
        localInitialWindowSize: 4,
        localMaximumPacketSize: 8,
      );
      expect(
        () => windowController.handleMessage(
          SSH_Message_Channel_Extended_Data(
            recipientChannel: 1,
            dataTypeCode: SSH_Message_Channel_Extended_Data.dataTypeStderr,
            data: Uint8List(5),
          ),
        ),
        throwsA(isA<SSHStateError>()),
      );

      await subscription.cancel();
    });
  });
}

SSHChannelController _createController({
  int localInitialWindowSize = 1024,
  int localMaximumPacketSize = 1024,
  int remoteInitialWindowSize = 0,
  void Function(SSHMessage)? sendMessage,
}) {
  return SSHChannelController(
    localId: 1,
    localMaximumPacketSize: localMaximumPacketSize,
    localInitialWindowSize: localInitialWindowSize,
    remoteId: 42,
    remoteMaximumPacketSize: 1024,
    remoteInitialWindowSize: remoteInitialWindowSize,
    sendMessage: sendMessage ?? (_) {},
  );
}
