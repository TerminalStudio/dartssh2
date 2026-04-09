import 'dart:convert';

import 'package:dartssh2/src/http/line_decoder.dart';
import 'package:test/test.dart';

void main() {
  group('LineDecoder', () {
    late LineDecoder decoder;
    late List<String> linesReceived;
    late List<int> lengthsReceived;

    setUp(() {
      linesReceived = [];
      lengthsReceived = [];
      decoder =
          LineDecoder.withCallback((String line, int length, LineDecoder self) {
        linesReceived.add(line);
        lengthsReceived.add(length);
      });
    });

    test('should process complete lines correctly', () {
      decoder.add(utf8.encode('line 1\nline 2\n'));
      expect(linesReceived, equals(['line 1\n', 'line 2\n']));
      expect(lengthsReceived, equals([7, 7]));
    });

    test('should process partial lines and buffer correctly', () {
      decoder.add(utf8.encode('partial line'));
      expect(linesReceived, isEmpty);
      expect(decoder.bufferedBytes,
          equals(12)); // Verifica que la línea esté en el buffer

      decoder.add(utf8.encode(' complete\n'));
      expect(linesReceived, equals(['partial line complete\n']));
      expect(lengthsReceived, equals([22]));
    });

    test('should handle lines split across multiple chunks', () {
      decoder.add(utf8.encode('line part 1'));
      decoder.add(utf8.encode(' part 2\n'));
      expect(linesReceived, equals(['line part 1 part 2\n']));
      expect(lengthsReceived, equals([19]));
    });

    test('should handle an empty chunk correctly', () {
      decoder.add([]);
      expect(linesReceived, isEmpty);
    });

    test('should correctly call callback on close with remaining buffered data',
        () {
      decoder.add(utf8.encode('final line without newline'));
      decoder.close();
      expect(linesReceived, equals(['final line without newline']));
      expect(lengthsReceived, equals([26]));
    });

    test('should process multiple lines in a single chunk', () {
      decoder.add(utf8.encode('line 1\nline 2\nline 3\n'));
      expect(linesReceived, equals(['line 1\n', 'line 2\n', 'line 3\n']));
      expect(lengthsReceived, equals([7, 7, 7]));
    });

    test('should handle expected byte count processing correctly', () {
      decoder.expectedByteCount = 10;
      decoder.add(utf8.encode('short\nlongerline\n'));

      // Check that 'short\n' is processed correctly
      expect(
          linesReceived,
          equals([
            'short\n'
                'long',
            'erline\n'
                ''
          ]));
      expect(lengthsReceived, equals([10, 7]));

      // Check the buffer is empty
      expect(decoder.bufferedBytes, equals(0));

      // On closing, ensure the remaining buffered line is processed
      decoder.close();
      expect(linesReceived.last, equals(''));
    });
  });
}
