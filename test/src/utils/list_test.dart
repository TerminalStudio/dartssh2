import 'package:dartssh2/src/utils/list.dart';
import 'package:test/test.dart';

void main() {
  group('randomBytes', () {
    test('returns the requested number of bytes', () {
      expect(randomBytes(0), isEmpty);
      expect(randomBytes(32), hasLength(32));
    });

    test('uses the full byte range', () {
      final bytes = randomBytes(65536);
      expect(bytes, contains(255));
    });
  });
}
