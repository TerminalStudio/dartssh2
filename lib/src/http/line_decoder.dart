import 'dart:convert';
import 'dart:typed_data';

// '\n' character
const int _lineTerminator = 10;

class LineDecoder {
  final BytesBuilder _unprocessedBytes = BytesBuilder();

  int expectedByteCount = -1;

  final void Function(String, int, LineDecoder) _callback;

  LineDecoder.withCallback(this._callback);

  void add(List<int> chunk) {
    while (chunk.isNotEmpty) {
      final splitIndex = expectedByteCount > 0
          ? expectedByteCount - _unprocessedBytes.length
          : chunk.indexOf(_lineTerminator) + 1;

      if (splitIndex > 0 && splitIndex <= chunk.length) {
        _unprocessedBytes.add(chunk.sublist(0, splitIndex));
        chunk = chunk.sublist(splitIndex);
        expectedByteCount = -1;
        _process(_unprocessedBytes.takeBytes());
      } else {
        _unprocessedBytes.add(chunk);
        chunk = [];
      }
    }
  }

  void _process(List<int> line) =>
      _callback(utf8.decoder.convert(line), line.length, this);

  int get bufferedBytes => _unprocessedBytes.length;

  void close() => _process(_unprocessedBytes.takeBytes());
}
