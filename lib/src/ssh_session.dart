import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/src/ssh_channel.dart';
import 'package:dartssh2/src/ssh_signal.dart';
import 'package:dartssh2/src/message/msg_channel.dart';
import 'package:dartssh2/src/utils/stream.dart';

/// A [SSHSession] represents a remote execution of a program.
class SSHSession {
  /// Stdin of the remote process. Close this to send EOF to the remote process.
  StreamSink<Uint8List> get stdin => _stdinController.sink;

  /// Stdout of the remote process.
  Stream<Uint8List> get stdout => _stdoutController.stream;

  /// Stderr of the remote process. May be empty if the remote process is
  /// started in pseudo terminal or remote ssh implementation does not support
  /// stderr.
  Stream<Uint8List> get stderr => _stderrController.stream;

  /// Exit code of the remote process. May be null if the process has not yet
  /// exited, the remote process has been terminated due to a signal, or the
  /// remote ssh implementation does not report exit codes.
  int? get exitCode => _exitCode;

  /// Information about the exit signal of a remote process. May be null if the
  /// process is still running, the remote process exited normally, or the
  /// remote ssh implementation does not report exit signals.
  SSHSessionExitSignal? get exitSignal => _exitSignal;

  /// This [Future] completes when the channel is closed. More data may still
  /// be available on the [stdout] and [stderr] streams at this time.
  Future<void> get done => _channel.done;

  SSHSession(this._channel) {
    _channel.setRequestHandler(_handleRequest);

    _channelDataSubscription = _channel.stream.listen(
      _handleChannelData,
      onDone: _handleChannelDataDone,
    );

    _stdinController.stream
        .transform(MaxChunkSize(_channel.maximumPacketSize))
        .map((data) => SSHChannelData(data))
        .pipe(_channel.sink);
  }

  final SSHChannel _channel;

  int? _exitCode;

  SSHSessionExitSignal? _exitSignal;

  late final StreamSubscription _channelDataSubscription;

  late final _stdinController = StreamController<Uint8List>();

  late final _stdoutController = StreamController<Uint8List>(
    onPause: _pauseChannelData,
    onResume: _resumeChannelData,
  );

  late final _stderrController = StreamController<Uint8List>(
    onPause: _pauseChannelData,
    onResume: _resumeChannelData,
  );

  /// Writes data to the stdin of the remote process. This is a convenience
  /// method that calls [stdin.add].
  void write(Uint8List data) {
    stdin.add(data);
  }

  /// Inform remote process of the current window size.
  void resizeTerminal(
    int width,
    int height, [
    int pixelWidth = 0,
    int pixelHeight = 0,
  ]) {
    if (width < 0) {
      throw ArgumentError.value(width, 'width', 'must be positive');
    }
    if (height < 0) {
      throw ArgumentError.value(height, 'height', 'must be positive');
    }
    if (pixelWidth < 0) {
      throw ArgumentError.value(pixelWidth, 'pixelWidth', 'must be positive');
    }
    if (pixelHeight < 0) {
      throw ArgumentError.value(pixelHeight, 'pixelHeight', 'must be positive');
    }
    _channel.sendTerminalWindowChange(
      width: width,
      height: height,
      pixelWidth: pixelWidth,
      pixelHeight: pixelHeight,
    );
  }

  /// Close the session. After this call, the session is no longer usable.
  void close() {
    _channel.close();
  }

  /// Deliver [signal] to the remote process. Some implementations may not
  /// support this.
  void kill(SSHSignal signal) {
    _channel.sendSignal(signal.name);
  }

  bool _handleRequest(SSH_Message_Channel_Request request) {
    switch (request.requestType) {
      case SSHChannelRequestType.exitStatus:
        _exitCode = request.exitStatus!;
        return true;
      case SSHChannelRequestType.exitSignal:
        _exitSignal = SSHSessionExitSignal(
          signalName: request.signalName!,
          coreDumped: request.coreDumped!,
          errorMessage: request.errorMessage!,
          languageTag: request.languageTag!,
        );
        return true;
    }
    return false;
  }

  void _pauseChannelData() {
    _channelDataSubscription.pause();
  }

  void _resumeChannelData() {
    _channelDataSubscription.resume();
  }

  void _handleChannelData(SSHChannelData data) {
    switch (data.type) {
      case null:
        return _stdoutController.add(data.bytes);
      case SSHChannelExtendedDataType.stderr:
        return _stderrController.add(data.bytes);
    }
  }

  void _handleChannelDataDone() {
    _stdoutController.close();
    _stderrController.close();
  }
}

/// Information about the exit signal of a remote process.
class SSHSessionExitSignal {
  /// Signal name without the leading "SIG".
  final String signalName;

  final bool coreDumped;

  /// An additional textual explanation of the error message
  final String errorMessage;

  final String languageTag;

  SSHSessionExitSignal({
    required this.signalName,
    required this.coreDumped,
    required this.errorMessage,
    required this.languageTag,
  });
}
