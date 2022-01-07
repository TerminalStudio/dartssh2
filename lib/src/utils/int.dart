import 'dart:typed_data';

extension IntX on int {
  /// Returns a [Uint8List] with the bytes of the integer encoded in [endian].
  Uint8List toUint32([Endian endian = Endian.big]) {
    final result = ByteData(4);
    result.setUint32(0, this, endian);
    return result.buffer.asUint8List();
  }

  /// Returns a [Uint8List] with the bytes of the integer encoded in [endian].
  Uint8List toUint64([Endian endian = Endian.big]) {
    final result = ByteData(8);
    result.setUint64(0, this, endian);
    return result.buffer.asUint8List();
  }

  /// Returns the octal representation of this integer.
  String toOctal() {
    return toRadixString(8);
  }

  /// Returns a colon-separated hex representation of this integer.
  String toColonHex() {
    return toRadixString(16)
        .padLeft(8, '0')
        .replaceAllMapped(RegExp(r'(..)'), (match) => ':${match[1]}');
  }
}
