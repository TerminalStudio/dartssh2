import 'dart:typed_data';

import 'package:dartssh2/src/kex/private_scalar.dart';
import 'package:pointycastle/ecc/curves/secp521r1.dart';
import 'package:test/test.dart';

void main() {
  final order = ECCurve_secp521r1().n;
  const byteLength = 66;

  group('generateEcPrivateScalar', () {
    test('uses all 521 bits and masks unused high bits', () {
      var requestedLength = 0;
      final input = Uint8List(byteLength)..[0] = 0xff;

      final scalar = generateEcPrivateScalar(
        order,
        randomBytes: (length) {
          requestedLength = length;
          return input;
        },
      );

      expect(requestedLength, byteLength);
      expect(scalar, BigInt.one << 520);
      expect(input[0], 0xff, reason: 'The source buffer must not be modified.');
    });

    test('rejects zero', () {
      var calls = 0;

      final scalar = generateEcPrivateScalar(
        order,
        randomBytes: (_) {
          calls++;
          if (calls == 1) return Uint8List(byteLength);
          return Uint8List(byteLength)..[byteLength - 1] = 1;
        },
      );

      expect(calls, 2);
      expect(scalar, BigInt.one);
    });

    test('rejects the curve order', () {
      var calls = 0;

      final scalar = generateEcPrivateScalar(
        order,
        randomBytes: (_) {
          calls++;
          if (calls == 1) return _encodeUnsigned(order, byteLength);
          return Uint8List(byteLength)..[byteLength - 1] = 2;
        },
      );

      expect(calls, 2);
      expect(scalar, BigInt.two);
    });

    test('rejects a random byte source with the wrong length', () {
      expect(
        () => generateEcPrivateScalar(
          order,
          randomBytes: (_) => Uint8List(byteLength - 1),
        ),
        throwsArgumentError,
      );
    });
  });
}

Uint8List _encodeUnsigned(BigInt value, int length) {
  final result = Uint8List(length);
  for (var i = length - 1; i >= 0; i--) {
    result[i] = (value & BigInt.from(0xff)).toInt();
    value >>= 8;
  }
  return result;
}
