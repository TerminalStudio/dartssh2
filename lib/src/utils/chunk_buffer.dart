import 'dart:typed_data';

/// A buffer that can queue chunks of data and consume parts or all of them as
/// needed. Primarily used for reading data from a socket.
class ChunkBuffer {
  var _buffer = Uint8List(0);

  void add(Uint8List data) {
    if (_buffer.isEmpty) {
      _buffer = data;
    } else {
      var newBuffer = Uint8List(data.length + _buffer.length);
      newBuffer.setRange(0, _buffer.length, _buffer);
      newBuffer.setRange(_buffer.length, newBuffer.length, data);
      _buffer = newBuffer;
    }
  }

  Uint8List consume([int? length]) {
    if (length == null) {
      final result = _buffer;
      _buffer = Uint8List(0);
      return result;
    } else {
      final result = Uint8List.sublistView(data, 0, length);
      _buffer = Uint8List.sublistView(data, length, data.length);
      return result;
    }
  }

  void clear() {
    _buffer = Uint8List(0);
  }

  Uint8List get data {
    return _buffer;
  }

  Uint8List view(int start, int length) {
    return _buffer.sublist(start, start + length);
  }

  int get length {
    return _buffer.length;
  }

  bool get isEmpty {
    return _buffer.isEmpty;
  }

  bool get isNotEmpty {
    return _buffer.isNotEmpty;
  }

  ByteData get byteData {
    return ByteData.sublistView(data);
  }

  @override
  String toString() {
    return 'SSHChunkBuffer(length: $length)';
  }
}
