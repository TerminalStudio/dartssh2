import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/message/base.dart';
import 'package:test/test.dart';

void main() {
  group('SSHClient.forwardDynamic', () {
    test('waits for authentication before starting', () async {
      final client = SSHClient(
        _FakeSSHSocket(),
        username: 'demo',
        keepAliveInterval: null,
      );

      // This is an intentional unit-test shortcut that bypasses the full SSH
      // handshake. It simulates receiving SSH_Message_Userauth_Success and
      // injects it via client.handlePacket() to drive forwardDynamic's behavior
      // of waiting for authentication. This test only verifies that
      // forwardDynamic properly waits for auth to complete before proceeding.
      scheduleMicrotask(() {
        client.handlePacket(SSH_Message_Userauth_Success().encode());
      });

      final dynamicForward = await client.forwardDynamic(
        bindHost: '127.0.0.1',
        bindPort: 0,
      );

      expect(dynamicForward.port, greaterThan(0));
      expect(dynamicForward.isClosed, isFalse);

      await dynamicForward.close();
      expect(dynamicForward.isClosed, isTrue);

      client.close();
      await client.done;
    });
  });
}

class _FakeSSHSocket implements SSHSocket {
  final _inputController = StreamController<Uint8List>();
  final _doneCompleter = Completer<void>();

  @override
  Stream<Uint8List> get stream => _inputController.stream;

  @override
  StreamSink<List<int>> get sink => _NoopSink();

  @override
  Future<void> get done => _doneCompleter.future;

  @override
  Future<void> close() async {
    if (!_doneCompleter.isCompleted) {
      _doneCompleter.complete();
    }
    await _inputController.close();
  }

  @override
  void destroy() {
    if (!_doneCompleter.isCompleted) {
      _doneCompleter.complete();
    }
    unawaited(_inputController.close());
  }
}

class _NoopSink implements StreamSink<List<int>> {
  @override
  void add(List<int> data) {}

  @override
  void addError(Object error, [StackTrace? stackTrace]) {}

  @override
  Future<void> addStream(Stream<List<int>> stream) async {
    await for (final _ in stream) {}
  }

  @override
  Future<void> close() async {}

  @override
  Future<void> get done async {}
}
