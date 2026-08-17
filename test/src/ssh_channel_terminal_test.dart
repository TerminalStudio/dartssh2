import 'dart:async';

import 'package:dartssh2/src/message/msg_channel.dart';
import 'package:dartssh2/src/ssh_channel.dart';
import 'package:dartssh2/src/ssh_errors.dart';
import 'package:dartssh2/src/ssh_message.dart';
import 'package:test/test.dart';

void main() {
  group('SSHChannel terminal state', () {
    test(
      'remote close fails a pending request and rejects later requests',
      () async {
        final sent = <SSHMessage>[];
        final controller = _controller(sendMessage: sent.add);
        final pending = controller.channel.sendShell();
        final pendingExpectation = expectLater(
          pending,
          throwsA(isA<SSHStateError>()),
        );

        controller.handleMessage(
          SSH_Message_Channel_Close(recipientChannel: controller.localId),
        );

        await pendingExpectation;
        await expectLater(controller.channel.done, completes);

        final sentBeforeRetry = sent.length;
        await expectLater(
          controller.channel.sendShell(),
          throwsA(isA<SSHStateError>()),
        );
        expect(sent, hasLength(sentBeforeRetry));

        expect(() => controller.destroy(), returnsNormally);
      },
    );

    test('destroy fails pending requests and flushes idempotently', () async {
      final flushCompleter = Completer<void>();
      final controller = _controller(
        sendMessage: (_) {},
        onFlush: () => flushCompleter.future,
      );
      final request = controller.channel.sendExec('true');
      final flush = controller.channel.flush();
      final expectations = [
        expectLater(request, throwsA(isA<SSHStateError>())),
        expectLater(flush, throwsA(isA<SSHStateError>())),
      ];

      controller.destroy();
      controller.destroy();

      await Future.wait(expectations);
    });

    test('EOF alone does not terminate pending channel requests', () async {
      final controller = _controller(sendMessage: (_) {});
      final pending = controller.channel.sendShell();

      controller.handleMessage(
        SSH_Message_Channel_EOF(recipientChannel: controller.localId),
      );
      controller.handleMessage(
        SSH_Message_Channel_Success(recipientChannel: controller.localId),
      );

      await expectLater(pending, completion(isTrue));
      controller.destroy();
    });

    test('a completed request is unaffected by later destruction', () async {
      final controller = _controller(sendMessage: (_) {});
      final pending = controller.channel.sendShell();

      controller.handleMessage(
        SSH_Message_Channel_Success(recipientChannel: controller.localId),
      );
      controller.destroy();

      await expectLater(pending, completion(isTrue));
    });
  });
}

SSHChannelController _controller({
  required void Function(SSHMessage) sendMessage,
  Future<void> Function()? onFlush,
}) {
  return SSHChannelController(
    localId: 1,
    localMaximumPacketSize: 1024,
    localInitialWindowSize: 1024,
    remoteId: 2,
    remoteMaximumPacketSize: 1024,
    remoteInitialWindowSize: 0,
    sendMessage: sendMessage,
    onFlush: onFlush,
  );
}
