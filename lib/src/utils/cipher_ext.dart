import 'dart:typed_data';

import 'package:pointycastle/pointycastle.dart';

extension BlockCipherX on BlockCipher {
  Uint8List processAll(Uint8List data) {
    final result = Uint8List(data.length);

    if (data.length % blockSize != 0) {
      throw FormatException('input ${data.length} not multiple of $blockSize');
    }

    for (var offset = 0; offset < data.length; offset += blockSize) {
      processBlock(data, offset, result, offset);
    }

    return result;
  }
}

extension MacX on Mac {
  void updateAll(Uint8List data) {
    update(data, 0, data.length);
  }

  Uint8List finish() {
    final result = Uint8List(macSize);
    final resuitLength = doFinal(result, 0);
    if (resuitLength != macSize) throw FormatException('mac size mismatch');
    return result;
  }
}
