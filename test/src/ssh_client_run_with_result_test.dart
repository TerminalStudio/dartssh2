import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/message/base.dart';
import 'package:dartssh2/src/ssh_channel.dart';
import 'package:test/test.dart';

void main() {
  group('SSHClient.runWithResult', () {
    test('captures stdout/stderr and exit status', () async {
      final harness = _SessionHarness();
      final client = _TestSSHClient(() async {
        scheduleMicrotask(() {
          harness.sendStdout('out\n');
          harness.sendStderr('err\n');
          harness.sendExitStatus(7);
          harness.close();
        });
        return harness.session;
      });

      final result = await client.runWithResult('cmd');

      expect(utf8.decode(result.stdout), 'out\n');
      expect(utf8.decode(result.stderr), 'err\n');
      expect(utf8.decode(result.output), 'out\nerr\n');
      expect(result.exitCode, 7);
      expect(result.exitSignal, isNull);

      harness.dispose();
      client.close();
    });

    test('respects stdout/stderr capture flags', () async {
      final harness = _SessionHarness();
      final client = _TestSSHClient(() async {
        scheduleMicrotask(() {
          harness.sendStdout('hidden\n');
          harness.sendStderr('visible\n');
          harness.sendExitStatus(0);
          harness.close();
        });
        return harness.session;
      });

      final result = await client.runWithResult(
        'cmd',
        stdout: false,
        stderr: true,
      );

      expect(result.stdout, isEmpty);
      expect(utf8.decode(result.stderr), 'visible\n');
      expect(utf8.decode(result.output), 'visible\n');
      expect(result.exitCode, 0);

      harness.dispose();
      client.close();
    });

    test('returns empty output when both captures are disabled', () async {
      final harness = _SessionHarness();
      final client = _TestSSHClient(() async {
        scheduleMicrotask(() {
          harness.sendStdout('hidden\n');
          harness.sendStderr('hidden-too\n');
          harness.sendExitSignal('TERM');
          harness.close();
        });
        return harness.session;
      });

      final result = await client.runWithResult(
        'cmd',
        stdout: false,
        stderr: false,
      );

      expect(result.output, isEmpty);
      expect(result.stdout, isEmpty);
      expect(result.stderr, isEmpty);
      expect(result.exitCode, isNull);
      expect(result.exitSignal?.signalName, 'TERM');

      harness.dispose();
      client.close();
    });

    test('run() returns combined output bytes', () async {
      final harness = _SessionHarness();
      final client = _TestSSHClient(() async {
        scheduleMicrotask(() {
          harness.sendStdout('one\n');
          harness.sendStderr('two\n');
          harness.sendExitStatus(0);
          harness.close();
        });
        return harness.session;
      });

      final output = await client.run('cmd');

      expect(utf8.decode(output), 'one\ntwo\n');

      harness.dispose();
      client.close();
    });
  });
}

class _TestSSHClient extends SSHClient {
  final Future<SSHSession> Function() _executeImpl;

  _TestSSHClient(this._executeImpl)
      : super(
          _FakeSSHSocket(),
          username: 'demo',
        );

  @override
  Future<SSHSession> execute(
    String command, {
    SSHPtyConfig? pty,
    SSHX11Config? x11,
    Map<String, String>? environment,
  }) {
    return _executeImpl();
  }
}

class _SessionHarness {
  _SessionHarness() {
    _controller = SSHChannelController(
      localId: 1,
      localMaximumPacketSize: 1024 * 1024,
      localInitialWindowSize: 1024 * 1024,
      remoteId: 2,
      remoteMaximumPacketSize: 1024 * 1024,
      remoteInitialWindowSize: 1024 * 1024,
      sendMessage: (_) {},
    );
    session = SSHSession(_controller.channel);
  }

  late final SSHChannelController _controller;
  late final SSHSession session;

  void sendStdout(String text) {
    _controller.handleMessage(
      SSH_Message_Channel_Data(
        recipientChannel: _controller.localId,
        data: Uint8List.fromList(utf8.encode(text)),
      ),
    );
  }

  void sendStderr(String text) {
    _controller.handleMessage(
      SSH_Message_Channel_Extended_Data(
        recipientChannel: _controller.localId,
        dataTypeCode: SSH_Message_Channel_Extended_Data.dataTypeStderr,
        data: Uint8List.fromList(utf8.encode(text)),
      ),
    );
  }

  void sendExitStatus(int code) {
    _controller.handleMessage(
      SSH_Message_Channel_Request.exitStatus(
        recipientChannel: _controller.localId,
        exitStatus: code,
      ),
    );
  }

  void sendExitSignal(String signalName) {
    _controller.handleMessage(
      SSH_Message_Channel_Request.exitSignal(
        recipientChannel: _controller.localId,
        exitSignalName: signalName,
        errorMessage: '',
        languageTag: '',
      ),
    );
  }

  void close() {
    _controller.handleMessage(
      SSH_Message_Channel_Close(recipientChannel: _controller.localId),
    );
  }

  void dispose() {
    _controller.destroy();
  }
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
