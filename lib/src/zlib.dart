// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

/*
import 'dart:typed_data';

import 'package:archive/src/zlib/deflate.dart';
import 'package:archive/src/zlib/inflate.dart';

class ArchiveInflateReader {
  Inflate zreader = Inflate.stream();
  Uint8List convert(Uint8List input) {
    zreader.streamInput(input);
    return Uint8List.fromList(zreader.inflateNext());
  }
}

class ArchiveDeflateWriter {
  Deflate zwriter = Deflate.buffer(null);
  Uint8List convert(Uint8List input) {
    zwriter.addBytes(input, flush: Deflate.PARTIAL_FLUSH);
    return zwriter.takeBytes();
  }
}*/
