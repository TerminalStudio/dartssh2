import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:test/test.dart';

void main() {
  group('SSHClient.ident', () {
    test('uses default ident when not provided', () async {
      final socket = _FakeSSHSocket();
      final client = SSHClient(
        socket,
        username: 'demo',
      );

      await Future<void>.delayed(Duration.zero);

      expect(client.ident, 'DartSSH_2.0');
      expect(socket.writes, contains('SSH-2.0-DartSSH_2.0\r\n'));

      client.close();
    });

    test('uses custom ident when provided', () async {
      final socket = _FakeSSHSocket();
      final client = SSHClient(
        socket,
        username: 'demo',
        ident: 'MyClient_1.0',
      );

      await Future<void>.delayed(Duration.zero);

      expect(client.ident, 'MyClient_1.0');
      expect(socket.writes, contains('SSH-2.0-MyClient_1.0\r\n'));

      client.close();
    });

    test('throws when ident is empty', () {
      expect(
        () => SSHClient(
          _FakeSSHSocket(),
          username: 'demo',
          ident: '',
        ),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('throws when ident contains newline characters', () {
      expect(
        () => SSHClient(
          _FakeSSHSocket(),
          username: 'demo',
          ident: 'Bad\nIdent',
        ),
        throwsA(isA<ArgumentError>()),
      );

      expect(
        () => SSHClient(
          _FakeSSHSocket(),
          username: 'demo',
          ident: 'Bad\rIdent',
        ),
        throwsA(isA<ArgumentError>()),
      );
    });
  });
}

class _FakeSSHSocket implements SSHSocket {
  final _inputController = StreamController<Uint8List>();
  final _doneCompleter = Completer<void>();
  final writes = <String>[];

  @override
  Stream<Uint8List> get stream => _inputController.stream;

  @override
  StreamSink<List<int>> get sink => _RecordingSink(writes);

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
  _RecordingSink(this._writes);

  final List<String> _writes;

  @override
  void add(List<int> data) {
    _writes.add(latin1.decode(data));
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
