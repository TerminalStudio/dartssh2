import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:test/test.dart';

void main() {
  group('SSH transport version exchange', () {
    test('accepts SSH-1.99 server banner', () async {
      final socket = _FakeSSHSocket();
      final client = SSHClient(
        socket,
        username: 'demo',
      );

      socket.addIncoming('SSH-1.99-OpenSSH_3.6.1p2\r\n');
      await _pumpUntil(() => client.remoteVersion != null);

      expect(client.remoteVersion, 'SSH-1.99-OpenSSH_3.6.1p2');

      client.close();
    });

    test('rejects non SSH-2 compatible server banners', () async {
      final socket = _FakeSSHSocket();
      final client = SSHClient(
        socket,
        username: 'demo',
      );

      socket.addIncoming('SSH-1.5-OpenSSH_1.2\r\n');

      await expectLater(
        client.authenticated,
        throwsA(
          predicate((error) {
            return error is SSHAuthAbortError &&
                error.reason is SSHHandshakeError;
          }),
        ),
      );

      client.close();
    });
  });
}

Future<void> _pumpUntil(bool Function() condition) async {
  for (var i = 0; i < 50; i++) {
    if (condition()) {
      return;
    }
    await Future<void>.delayed(const Duration(milliseconds: 10));
  }
  fail('Timed out waiting for condition');
}

class _FakeSSHSocket implements SSHSocket {
  final _inputController = StreamController<Uint8List>();
  final _doneCompleter = Completer<void>();
  final _sink = _RecordingSink();

  @override
  Stream<Uint8List> get stream => _inputController.stream;

  @override
  StreamSink<List<int>> get sink => _sink;

  @override
  Future<void> get done => _doneCompleter.future;

  void addIncoming(String data) {
    _inputController.add(Uint8List.fromList(latin1.encode(data)));
  }

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

class _RecordingSink implements StreamSink<List<int>> {
  @override
  void add(List<int> data) {
    // SSHTransport writes protocol lines and packets to the sink.
    latin1.decode(data);
  }

  @override
  void addError(Object error, [StackTrace? stackTrace]) {}

  @override
  Future<void> addStream(Stream<List<int>> stream) async {
    await for (final data in stream) {
      add(data);
    }
  }

  @override
  Future<void> close() async {}

  @override
  Future<void> get done async {}
}
