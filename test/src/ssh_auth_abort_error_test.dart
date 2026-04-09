import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:test/test.dart';

void main() {
  group('SSHAuthAbortError', () {
    test('supports constructor without reason for backward compatibility', () {
      final error = SSHAuthAbortError('aborted');

      expect(error.message, 'aborted');
      expect(error.reason, isNull);
    });

    test('stores provided reason', () {
      final reason = SSHSocketError('boom');
      final error = SSHAuthAbortError('aborted', reason);

      expect(error.reason, same(reason));
    });
  });

  group('SSHClient auth abort reason', () {
    test('is null when transport closes without underlying error', () async {
      final socket = _FakeSSHSocket();
      final client = SSHClient(
        socket,
        username: 'demo',
      );

      await socket.close();

      await expectLater(
        client.authenticated,
        throwsA(
          predicate((error) {
            return error is SSHAuthAbortError && error.reason == null;
          }),
        ),
      );

      client.close();
    });
  });
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
    // Transport writes SSH version banner here; decode to validate data is valid bytes.
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
