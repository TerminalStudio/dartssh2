import 'dart:typed_data';

import 'package:dartssh2/src/utils/bigint.dart';
import 'package:dartssh2/src/utils/list.dart' as list_utils;

/// Generates an unbiased private scalar in the range `1 <= scalar < order`.
BigInt generateEcPrivateScalar(
  BigInt order, {
  Uint8List Function(int length)? randomBytes,
}) {
  if (order <= BigInt.one) {
    throw ArgumentError.value(order, 'order', 'Must be greater than one');
  }

  final bitLength = order.bitLength;
  final byteLength = (bitLength + 7) ~/ 8;
  final excessBits = byteLength * 8 - bitLength;
  final byteSource = randomBytes ?? list_utils.randomBytes;

  while (true) {
    final bytes = Uint8List.fromList(byteSource(byteLength));
    if (bytes.length != byteLength) {
      throw ArgumentError(
        'Random byte source must return exactly $byteLength bytes',
      );
    }

    if (excessBits != 0) {
      bytes[0] &= 0xff >> excessBits;
    }

    final candidate = decodeBigIntWithSign(1, bytes);
    if (candidate > BigInt.zero && candidate < order) {
      return candidate;
    }
  }
}
