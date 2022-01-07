import 'dart:math';

import 'dart:typed_data';

Uint8List randomBytes(int length) {
  final random = Random();
  final bytes = Uint8List(length);
  for (var i = 0; i < length; i++) {
    bytes[i] = random.nextInt(255);
  }
  return bytes;
}

extension ListX<T> on List<T> {
  bool equals(List<T> other) {
    if (other.length != length) return false;
    for (int i = 0; i < length; i++) {
      if (this[i] != other[i]) return false;
    }
    return true;
  }
}
