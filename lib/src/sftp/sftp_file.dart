part of 'sftp_client.dart';

/// Represents an opened file handle on the remote SFTP server.
class SftpFile {
  final Uint8List _handle;

  final SftpClient _client;

  /// Creates an [SftpFile] representing an open handle on the remote server.
  SftpFile(this._client, this._handle);

  var _isClosed = false;

  /// Whether this file handle has been closed.
  bool get isClosed => _isClosed;

  /// Closes the file handle on the remote SFTP server.
  Future<void> close() async {
    if (_isClosed) return;
    _isClosed = true;
    await _client._close(_handle);
  }

  /// Retrieves metadata and attributes for this open file handle.
  Future<SftpFileAttrs> stat() async {
    _mustNotBeClosed();
    final reply = await _client._sendFStat(_handle);
    if (reply is SftpAttrsPacket) return reply.attrs;
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    throw SftpStatusError.fromStatus(reply);
  }

  /// Updates metadata and attributes for this open file handle.
  Future<void> setStat(SftpFileAttrs attrs) async {
    _mustNotBeClosed();
    final reply = await _client._sendFSetStat(_handle, attrs);
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    SftpStatusError.check(reply);
  }

  /// Reads at most [length] bytes from the file starting at [offset]. If
  /// [length] is null, reads until end of file. Returns a [Stream] of chunks
  /// ordered by file offset, even if the server replies out of order.
  /// [onProgress] is called with the total number of bytes already read.
  /// Use [readBytes] if you want a single Uint8List.
  Stream<Uint8List> read({
    int? length,
    int offset = 0,
    void Function(int bytesRead)? onProgress,
    int chunkSize = _kReadChunkSize,
    int maxPendingRequests = _kReadMaxPendingRequests,
  }) async* {
    _mustNotBeClosed();
    if (chunkSize <= 0) {
      throw ArgumentError.value(chunkSize, 'chunkSize', 'must be positive');
    }
    if (maxPendingRequests <= 0) {
      throw ArgumentError.value(
        maxPendingRequests,
        'maxPendingRequests',
        'must be positive',
      );
    }

    // Get the file size if not specified.
    if (length == null) {
      final fileStat = await stat();
      final fileSize = fileStat.size;

      if (fileSize == null) {
        throw SftpError('Can not get file size');
      }

      length = fileSize - offset;
    }

    if (length == 0) return;

    if (length < 0) {
      throw SftpError('Length must be positive: $length');
    }

    final endOffset = offset + length;
    final completedReads = <int, Uint8List?>{};
    var reservedOffset = offset;
    var bytesRead = 0;
    var nextOutputOffset = offset;
    var pendingReadCount = 0;
    var activeReadLimit = 1;
    var effectiveChunkSize = chunkSize;
    var stopScheduling = false;
    var outputEnded = false;
    Object? pendingError;
    StackTrace? pendingStackTrace;
    Completer<void>? completionSignal;

    void notifyReadComplete() {
      final signal = completionSignal;
      if (signal != null && !signal.isCompleted) {
        signal.complete();
      }
    }

    Future<void> waitForReadComplete() {
      final signal = completionSignal = Completer<void>();
      return signal.future.whenComplete(() {
        if (identical(completionSignal, signal)) {
          completionSignal = null;
        }
      });
    }

    void recordError(Object error, StackTrace stackTrace) {
      if (pendingError != null) return;
      pendingError = error;
      pendingStackTrace = stackTrace;
      stopScheduling = true;
    }

    void issueRead(int startOffset, int requestLength) {
      pendingReadCount++;
      _readChunk(requestLength, startOffset).then(
        (chunk) {
          pendingReadCount--;

          if (pendingError != null) {
            notifyReadComplete();
            return;
          }

          if (chunk == null) {
            stopScheduling = true;
            completedReads[startOffset] = null;
            notifyReadComplete();
            return;
          }

          if (chunk.length > requestLength) {
            recordError(
              SftpError(
                'Received ${chunk.length} bytes for a $requestLength-byte read',
              ),
              StackTrace.current,
            );
            notifyReadComplete();
            return;
          }

          if (chunk.isEmpty) {
            recordError(
              SftpError('Unexpected empty data chunk before EOF'),
              StackTrace.current,
            );
            notifyReadComplete();
            return;
          }

          activeReadLimit = min(maxPendingRequests, activeReadLimit + 1);
          completedReads[startOffset] = chunk;

          if (chunk.length < requestLength) {
            // OpenSSH clamps the request size down to a short reply, with a
            // 512 byte floor (`MIN_READ_SIZE` in `sftp-client.c`). We clamp
            // the same way, but only when the reply is large enough to look
            // like the server's real capacity. Clamping to the floor instead
            // would let a single tiny reply pin every later request at 512
            // bytes for the rest of the transfer, which costs far more here
            // than it does in OpenSSH: this pipeline defaults to 64 KB reads
            // with up to 128 of them in flight.
            if (chunk.length >= _kMinReadSize) {
              effectiveChunkSize = min(effectiveChunkSize, chunk.length);
            }
            issueRead(
              startOffset + chunk.length,
              requestLength - chunk.length,
            );
          }

          notifyReadComplete();
        },
        onError: (Object error, StackTrace stackTrace) {
          pendingReadCount--;
          recordError(error, stackTrace);
          notifyReadComplete();
        },
      );
    }

    void scheduleReads() {
      while (!stopScheduling &&
          reservedOffset < endOffset &&
          pendingReadCount < activeReadLimit &&
          completedReads.length < maxPendingRequests) {
        final startOffset = reservedOffset;
        final requestLength =
            min(effectiveChunkSize, endOffset - reservedOffset);
        issueRead(startOffset, requestLength);
        reservedOffset += requestLength;
      }
    }

    scheduleReads();

    while (bytesRead < length) {
      if (pendingError != null) {
        Error.throwWithStackTrace(pendingError!, pendingStackTrace!);
      }

      if (!outputEnded && completedReads.containsKey(nextOutputOffset)) {
        final chunk = completedReads.remove(nextOutputOffset);
        if (chunk == null) {
          outputEnded = true;
        } else {
          nextOutputOffset += chunk.length;
          bytesRead += chunk.length;
          scheduleReads();

          yield chunk;
          onProgress?.call(bytesRead);
          continue;
        }
      }

      scheduleReads();
      if (outputEnded) {
        if (pendingReadCount == 0) break;
      } else if (pendingReadCount == 0) {
        break;
      }
      await waitForReadComplete();
    }
  }

  /// Downloads this file into [destination].
  ///
  /// Returns the total number of bytes written.
  Future<int> downloadTo(
    StreamSink<List<int>> destination, {
    int? length,
    int offset = 0,
    void Function(int bytesRead)? onProgress,
    int chunkSize = _kDownloadChunkSize,
    int maxPendingRequests = _kDownloadMaxPendingRequests,
    bool closeDestination = false,
  }) async {
    _mustNotBeClosed();
    var bytesRead = 0;

    try {
      await destination.addStream(
        read(
          length: length,
          offset: offset,
          onProgress: (value) {
            bytesRead = value;
            onProgress?.call(value);
          },
          chunkSize: chunkSize,
          maxPendingRequests: maxPendingRequests,
        ),
      );
    } finally {
      if (closeDestination) {
        await destination.close();
      }
    }

    return bytesRead;
  }

  /// Downloads this file into a random-access local file.
  ///
  /// Unlike [read] and [downloadTo], this method does not require SFTP read
  /// replies to be yielded in offset order. Replies are written to
  /// [destination] at the same offset, allowing pipelined reads to make
  /// progress even when later offsets complete before earlier ones.
  ///
  /// Returns the total number of bytes written.
  Future<int> downloadToRandomAccess(
    RandomAccessFile destination, {
    int? length,
    int offset = 0,
    void Function(int bytesRead)? onProgress,
    int chunkSize = _kDownloadChunkSize,
    int maxPendingRequests = _kDownloadMaxPendingRequests,
  }) async {
    _mustNotBeClosed();
    if (chunkSize <= 0) {
      throw ArgumentError.value(chunkSize, 'chunkSize', 'must be positive');
    }
    if (maxPendingRequests <= 0) {
      throw ArgumentError.value(
        maxPendingRequests,
        'maxPendingRequests',
        'must be positive',
      );
    }

    if (length == null) {
      final fileSize = (await stat()).size;
      if (fileSize == null) {
        throw SftpError('Can not get file size');
      }
      length = fileSize - offset;
    }

    if (length == 0) return 0;
    if (length < 0) {
      throw SftpError('Length must be positive: $length');
    }

    final endOffset = offset + length;
    final completionQueue = <_ReadCompletion>[];
    var reservedOffset = offset;
    var bytesWritten = 0;
    var pendingReadCount = 0;
    var activeReadLimit = 1;
    var effectiveChunkSize = chunkSize;
    Object? pendingError;
    StackTrace? pendingStackTrace;
    Completer<void>? completionSignal;

    void notifyReadComplete() {
      final signal = completionSignal;
      if (signal != null && !signal.isCompleted) {
        signal.complete();
      }
    }

    Future<void> waitForReadComplete() {
      if (completionQueue.isNotEmpty || pendingError != null) {
        return Future.value();
      }
      final signal = completionSignal = Completer<void>();
      return signal.future.whenComplete(() {
        if (identical(completionSignal, signal)) {
          completionSignal = null;
        }
      });
    }

    void issueRead(int startOffset, int requestLength) {
      pendingReadCount++;
      _readChunk(requestLength, startOffset).then(
        (chunk) {
          pendingReadCount--;
          if (chunk != null && chunk.isNotEmpty) {
            activeReadLimit = min(maxPendingRequests, activeReadLimit + 1);
          }
          completionQueue.add(_ReadCompletion(startOffset, chunk));
          if (chunk != null &&
              chunk.isNotEmpty &&
              chunk.length < requestLength &&
              startOffset + chunk.length < endOffset) {
            effectiveChunkSize = max(1, min(effectiveChunkSize, chunk.length));
            issueRead(
              startOffset + chunk.length,
              min(
                requestLength - chunk.length,
                endOffset - startOffset - chunk.length,
              ),
            );
          }
          notifyReadComplete();
        },
        onError: (Object error, StackTrace stackTrace) {
          pendingReadCount--;
          pendingError = error;
          pendingStackTrace = stackTrace;
          notifyReadComplete();
        },
      );
    }

    void scheduleReads() {
      while (reservedOffset < endOffset && pendingReadCount < activeReadLimit) {
        final startOffset = reservedOffset;
        final requestLength =
            min(effectiveChunkSize, endOffset - reservedOffset);
        issueRead(startOffset, requestLength);
        reservedOffset += requestLength;
      }
    }

    scheduleReads();

    while (bytesWritten < length) {
      if (pendingError != null) {
        Error.throwWithStackTrace(pendingError!, pendingStackTrace!);
      }

      if (completionQueue.isEmpty) {
        if (pendingReadCount == 0) break;
        await waitForReadComplete();
        continue;
      }

      final completion = completionQueue.removeAt(0);
      final startOffset = completion.startOffset;
      final chunk = completion.chunk;
      if (chunk == null) break;
      if (chunk.isEmpty) {
        throw SftpError('Unexpected empty data chunk before EOF');
      }

      final remaining = length - (startOffset - offset);
      final outputChunk = chunk.length <= remaining
          ? chunk
          : Uint8List.sublistView(chunk, 0, remaining);
      await destination.setPosition(startOffset);
      await destination.writeFrom(outputChunk);

      bytesWritten += outputChunk.length;
      onProgress?.call(bytesWritten);
      scheduleReads();
    }

    if (bytesWritten != length) {
      throw SftpError(
        'Incomplete download: received $bytesWritten of $length bytes',
      );
    }

    return bytesWritten;
  }

  /// Reads at most [length] bytes from the file starting at [offset]. If
  /// [length] is null, reads until end of the file.
  /// Use [read] if you want to stream large file in chunks.
  Future<Uint8List> readBytes({int? length, int offset = 0}) async {
    final buffer = BytesBuilder(copy: false);
    await for (final chunk in read(length: length, offset: offset)) {
      buffer.add(chunk);
    }
    return buffer.takeBytes();
  }

  /// Writes [stream] to the file starting at [offset].
  ///
  /// Returns a [SftpFileWriter] that can be used to control the write
  /// operation or wait for it to complete.
  SftpFileWriter write(
    Stream<Uint8List> stream, {
    int offset = 0,
    void Function(int total)? onProgress,
  }) {
    return SftpFileWriter(this, stream, offset, onProgress);
  }

  /// Writes [data] to the file starting at [offset].
  Future<void> writeBytes(Uint8List data, {int offset = 0}) async {
    _mustNotBeClosed();
    const maxChunkSize = 16 * 1024;
    var bytesSent = 0;
    final futures = <Future<void>>[];
    while (bytesSent < data.length) {
      final chunkSize = min(data.length - bytesSent, maxChunkSize);
      final chunkBegin = bytesSent;
      final chunkEnd = chunkBegin + chunkSize;
      final chunk = Uint8List.sublistView(data, chunkBegin, chunkEnd);
      futures.add(_writeChunk(chunk, offset: offset + bytesSent));
      bytesSent += chunkSize;
    }
    await Future.wait(futures);
  }

  /// Gets filesystem statistics that this file is on.
  ///
  /// **Note**: This is an extension to the SFTP protocol, supported by most
  /// openssh servers. A [SftpExtensionError] is thrown if the server does not
  /// support this extension.
  ///
  /// See also:
  ///
  /// * [SftpClient.statvfs] which takes a path instead of a file handle as
  ///   argument.
  Future<SftpStatVfs> statvfs() async {
    _mustNotBeClosed();
    await _client._checkExtension('fstatvfs@openssh.com', '2');
    final payload = SftpFstatVfsRequest(handle: _handle);
    final reply = await _client._sendExtended(payload);
    if (reply is SftpStatusPacket) throw SftpStatusError.fromStatus(reply);
    if (reply is! SftpExtendedReplyPacket) throw SftpError('Unexpected reply');
    final stat = SftpStatVfsReply.decode(reply.payload);
    return SftpStatVfs.fromReply(stat);
  }

  Future<void> _writeChunk(Uint8List data, {int offset = 0}) async {
    // print('_writeChunk: offset=$offset');
    _mustNotBeClosed();
    final reply = await _client._sendWrite(_handle, offset, data);
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    SftpStatusError.check(reply);
  }

  Future<Uint8List?> _readChunk(int length, [int offset = 0]) async {
    _mustNotBeClosed();
    final reply = await _client._sendRead(_handle, offset, length);
    if (reply is SftpDataPacket) return reply.data;
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    SftpStatusError.check(reply);
    return null;
  }

  void _mustNotBeClosed() {
    if (isClosed) throw SftpError('File is closed');
  }

  @override
  String toString() => 'SftpFile(0x${hex.encode(_handle)})';
}

/// Handshake information received from the SFTP server.
class SftpHandsake {
  /// Negotiated SFTP protocol version.
  final int version;

  /// Map of protocol extension names to version strings supported by server.
  final Map<String, String> extensions;

  /// Creates a container for SFTP handshake details.
  SftpHandsake(this.version, this.extensions);

  @override
  String toString() => 'SftpHandsake($version, $extensions)';
}

/// Tracks a pending SFTP read completion for [SftpFile.downloadToRandomAccess].
class _ReadCompletion {
  _ReadCompletion(this.startOffset, this.chunk);

  final int startOffset;
  final Uint8List? chunk;
}
