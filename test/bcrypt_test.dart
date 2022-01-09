import 'dart:typed_data';

import 'package:dartssh2/src/utils/bcrypt.dart';
import 'package:test/test.dart';

void main() {
  test('bcrypt_pbkdf', () {
    final passphrase = Uint8List.fromList(
      [49, 50, 51, 52, 53, 54],
    );

    final salt = Uint8List.fromList(
      [180, 151, 210, 40, 110, 7, 72, 146, 145, 81, 92, 133, 92, 72, 202, 61],
    );

    final output = Uint8List(48);

    bcrypt_pbkdf(
      passphrase,
      passphrase.lengthInBytes,
      salt,
      salt.lengthInBytes,
      output,
      output.lengthInBytes,
      16,
    );

    expect(
      output,
      Uint8List.fromList([
        176,
        247,
        9,
        83,
        159,
        104,
        252,
        200,
        108,
        121,
        127,
        254,
        249,
        17,
        36,
        46,
        110,
        105,
        124,
        105,
        58,
        131,
        59,
        151,
        33,
        134,
        88,
        36,
        11,
        191,
        130,
        97,
        65,
        69,
        243,
        216,
        159,
        223,
        179,
        176,
        185,
        5,
        228,
        254,
        245,
        2,
        178,
        59
      ]),
    );
  });
}
