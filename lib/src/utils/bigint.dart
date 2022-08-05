import 'dart:typed_data';

import 'package:meta/meta.dart';

final _byteMask = BigInt.from(0xff);
final _negativeFlag = BigInt.from(0x80);

/// Decode a big integer with arbitrary sign.
/// When:
/// sign == 0: Zero regardless of magnitude
/// sign < 0: Negative
/// sign > 0: Positive
@internal
BigInt decodeBigIntWithSign(int sign, List<int> magnitude) {
  if (sign == 0) {
    return BigInt.zero;
  }

  BigInt result;

  if (magnitude.length == 1) {
    result = BigInt.from(magnitude[0]);
  } else {
    result = BigInt.from(0);
    for (var i = 0; i < magnitude.length; i++) {
      var item = magnitude[magnitude.length - i - 1];
      result |= (BigInt.from(item) << (8 * i));
    }
  }

  if (result != BigInt.zero) {
    result = sign < 0
        ? result.toSigned(result.bitLength)
        : result.toUnsigned(result.bitLength);
  }
  return result;
}

/// Encode a BigInt into bytes using big-endian encoding.
/// It encodes the integer to a minimal twos-compliment integer as defined by
/// ASN.1
@internal
Uint8List encodeBigInt(BigInt? number) {
  if (number == BigInt.zero) {
    return Uint8List.fromList([0]);
  }

  int needsPaddingByte;
  int rawSize;

  if (number! > BigInt.zero) {
    rawSize = (number.bitLength + 7) >> 3;
    needsPaddingByte =
        ((number >> (rawSize - 1) * 8) & _negativeFlag) == _negativeFlag
            ? 1
            : 0;
  } else {
    needsPaddingByte = 0;
    rawSize = (number.bitLength + 8) >> 3;
  }

  final size = rawSize + needsPaddingByte;
  var result = Uint8List(size);
  for (var i = 0; i < rawSize; i++) {
    result[size - i - 1] = (number! & _byteMask).toInt();
    number = number >> 8;
  }
  return result;
}

/// Encode as Big Endian unsigned byte array.
@internal
Uint8List encodeBigIntAsUnsigned(BigInt number) {
  if (number == BigInt.zero) {
    return Uint8List.fromList([0]);
  }
  var size = number.bitLength + (number.isNegative ? 8 : 7) >> 3;
  var result = Uint8List(size);
  for (var i = 0; i < size; i++) {
    result[size - i - 1] = (number & _byteMask).toInt();
    number = number >> 8;
  }
  return result;
}
