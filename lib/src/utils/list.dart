import 'dart:math';

import 'dart:typed_data';

final _secureRandom = Random.secure();

Uint8List randomBytes(int length) {
  final bytes = Uint8List(length);
  for (var i = 0; i < length; i++) {
    bytes[i] = _secureRandom.nextInt(256);
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
