import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/src/sftp/sftp_client.dart';
import 'package:dartssh2/src/utils/stream.dart';

/// The amount of data to send in a single SFTP packet.
///
/// From the SFTP spec it's safe to send up to 32KB of data in a single packet.
/// To strike a balance between capability and performance, we choose 16KB.
const chunkSize = 16 * 1024;

/// The maximum amount of data that can be sent to the remote host without
/// receiving an acknowledgement.
const maxBytesOnTheWire = chunkSize * 64;

/// Holds the state of a streaming write operation from [stream] to [file].
class SftpFileWriter {
  /// The remote file to write to.
  final SftpFile file;

  /// The stream of data to write to [file].
  final Stream<Uint8List> stream;

  /// The offset in [file] to start writing to.
  final int offset;

  /// Called when [bytes] of data have been successfully written to [file].
  final Function(int bytes)? onProgress;

  /// Creates a new [SftpFileWriter]. The upload process is started immediately
  /// after construction.
  SftpFileWriter(this.file, this.stream, this.offset, this.onProgress) {
    _subscription =
        stream.transform(MaxChunkSize(chunkSize)).listen(_handleLocalData);

    _subscription.onDone(_handleLocalDone);
  }

  /// The subscription for [stream]. We use this to pause and resume the data
  /// source.
  late final StreamSubscription<Uint8List> _subscription;

  final _doneCompleter = Completer<void>();

  /// Bytes of data that have been sent to the remote host.
  var _bytesSent = 0;

  /// Bytes of data that have been acknowledged by the remote host.
  var _bytesAcked = 0;

  /// Number of bytes sent to the server but not yet acknowledged.
  ///
  /// This number is used to pause the stream when it gets too high.
  int get _bytesOnTheWire => _bytesSent - _bytesAcked;

  /// Whether [stream] has emitted all of its data.
  var _streamDone = false;

  /// A [Future] that completes when:
  ///
  /// - All data from [stream] has been written to [file]
  /// - Or the write operation has been aborted by calling [abort].
  Future<void> get done => _doneCompleter.future;

  /// Stops [stream] from emitting more data. Returns a [Future] that completes
  /// when the underlying data source of [stream] has been successfully closed.
  ///
  /// Calling [abort] will make [done] to complete immediately.
  Future<void> abort() async {
    _doneCompleter.complete();
    await _subscription.cancel();
  }

  /// Pauses [stream] from emitting more data. It's safe to call this even if
  /// the stream is already paused. Use [resume] to resume the operation.
  void pause() {
    if (!_subscription.isPaused) {
      _subscription.pause();
    }
  }

  /// Resumes [stream] after it has been paused. It's safe to call this even if
  /// the stream is not paused. Use [pause] to pause the operation.
  void resume() {
    _subscription.resume();
  }

  Future<void> _handleLocalData(Uint8List chunk) async {
    if (_bytesOnTheWire >= maxBytesOnTheWire) {
      _subscription.pause();
    } else {
      _subscription.resume();
    }

    final chunkWriteOffset = offset + _bytesSent;
    _bytesSent += chunk.length;
    await file.writeBytes(chunk, offset: chunkWriteOffset);

    _bytesAcked += chunk.length;
    onProgress?.call(_bytesAcked);

    if (_bytesOnTheWire < maxBytesOnTheWire) {
      _subscription.resume();
    }

    if (_streamDone && _bytesSent == _bytesAcked) {
      _doneCompleter.complete();
    }
  }

  void _handleLocalDone() {
    _streamDone = true;
  }
}
