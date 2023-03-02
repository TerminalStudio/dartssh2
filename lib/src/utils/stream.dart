import 'dart:async';
import 'dart:math';

import 'dart:typed_data';

import 'package:meta/meta.dart';

class MaxChunkSize extends StreamTransformerBase<Uint8List, Uint8List> {
  MaxChunkSize(this.size);

  final int size;

  @override
  Stream<Uint8List> bind(Stream<Uint8List> stream) async* {
    await for (var chunk in stream) {
      if (chunk.length < size) {
        yield chunk;
        continue;
      }

      final blocks = chunk.length ~/ size;

      for (var i = 0; i < blocks; i++) {
        yield Uint8List.sublistView(chunk, i * size, (i + 1) * size);
      }

      if (blocks * size < chunk.length) {
        yield Uint8List.sublistView(chunk, blocks * size);
      }
    }
  }
}

class MinChunkSize extends StreamTransformerBase<Uint8List, Uint8List> {
  MinChunkSize(this.size);

  final int size;

  var _yielded = false;

  @override
  Stream<Uint8List> bind(Stream<Uint8List> stream) async* {
    var buffer = BytesBuilder(copy: false);

    await for (var chunk in stream) {
      buffer.add(chunk);

      if (buffer.length < size) {
        continue;
      }

      yield buffer.takeBytes();
      _yielded = true;
    }

    if (buffer.isNotEmpty || !_yielded) {
      yield buffer.takeBytes();
    }
  }
}

/// A helper class that can be used to read data from a data stream on demand.
abstract class StreamConsumerBase<T> {
  /// Creates a new [StreamConsumer] that reads from [stream].
  ///
  /// The underlying [stream] is paused during calls to [read].
  StreamConsumerBase(Stream<T> stream) : _stream = StreamIterator(stream);

  /// The underlying stream being read from.
  final StreamIterator<T> _stream;

  /// The current chunk being read from. `null` when the next chunk needs to be
  /// read from the stream.
  T? _currentChunk;

  /// The amount of bytes that have been read from [_currentChunk].
  var _currentOffset = 0;

  @protected
  int getLength(T chunk);

  @protected
  T sublistView(T chunk, int start, int end);

  /// Reads up to [size] bytes from the stream.
  ///
  /// The returned data may be less than [size] if the end of the stream is
  /// reached or if chunk boundaries are encountered.
  ///
  /// Returns `null` if the end of the stream is reached.
  Future<T?> read(int size) async {
    if (_currentChunk == null) {
      if (!await _stream.moveNext()) {
        return null;
      }

      _currentChunk = _stream.current;
      _currentOffset = 0;
    }

    /// A fast path for the case where [_currentChunk] can be directly returned
    /// without creating a sublist view.
    if (_currentOffset == 0 && size >= getLength(_currentChunk as T)) {
      final result = _currentChunk;
      _currentChunk = null;
      return result;
    }

    final effectSize = min(
      size,
      getLength(_currentChunk as T) - _currentOffset,
    );

    final result = sublistView(
      _currentChunk as T,
      _currentOffset,
      _currentOffset + effectSize,
    );

    _currentOffset += effectSize;

    if (_currentOffset >= getLength(_currentChunk as T)) {
      _currentChunk = null;
    }

    return result;
  }

  /// Dispose the consumer and cancel the underlying stream.
  Future<void> cancel() async {
    await _stream.cancel();
  }
}

/// A helper class that can be used to read data from a byte stream on demand.
class StreamConsumer extends StreamConsumerBase<Uint8List> {
  StreamConsumer(Stream<Uint8List> stream) : super(stream);

  @override
  int getLength(Uint8List chunk) {
    return chunk.length;
  }

  @override
  Uint8List sublistView(Uint8List chunk, int start, int end) {
    return Uint8List.sublistView(chunk, start, end);
  }
}
