import 'dart:convert';
import 'dart:typed_data';

Uint8List utf8Encode(String input) {
  return Utf8Encoder().convert(input);
}

String utf8Decode(Uint8List input) {
  return Utf8Decoder().convert(input);
}
