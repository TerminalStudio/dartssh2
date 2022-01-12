import 'dart:async';

import 'dart:typed_data';

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
