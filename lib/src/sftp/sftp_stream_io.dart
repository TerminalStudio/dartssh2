import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/src/sftp/sftp_client.dart';

const chunkSize = 16 * 1024;
const maxBytesOnTheWire = chunkSize * 64;

class SftpFileWriter {
  final SftpFile file;

  final Stream<Uint8List> stream;

  final int offset;

  final Function(int)? onProgress;

  SftpFileWriter(this.file, this.stream, this.offset, this.onProgress) {
    _subscription = stream.listen(_onStreamData);
    _subscription.onDone(_onStreamDone);
  }

  late final StreamSubscription<Uint8List> _subscription;

  final _doneCompleter = Completer<void>();

  var _bytesSent = 0;

  var _bytesAcked = 0;

  var _streamDone = false;

  Future<void> get done => _doneCompleter.future;

  Future<void> _onStreamData(Uint8List chunk) async {
    final bytesOnTheWire = _bytesSent - _bytesAcked;
    if (bytesOnTheWire >= maxBytesOnTheWire) {
      _subscription.pause();
    }

    final chunkWriteOffset = offset + _bytesSent;
    _bytesSent += chunk.length;
    await file.writeBytes(chunk, offset: chunkWriteOffset);

    _bytesAcked += chunk.length;
    onProgress?.call(_bytesAcked);

    if (bytesOnTheWire < maxBytesOnTheWire) {
      _subscription.resume();
    }

    if (_streamDone && _bytesSent == _bytesAcked) {
      _doneCompleter.complete();
    }
  }

  void _onStreamDone() {
    _streamDone = true;
  }
}
