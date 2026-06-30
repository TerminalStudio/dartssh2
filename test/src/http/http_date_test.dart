import 'package:dartssh2/src/http/http_date.dart';
import 'package:test/test.dart';

void main() {
  group('parseHttpDate', () {
    test('parses IMF-fixdate', () {
      final d = parseHttpDate('Sun, 06 Nov 1994 08:49:37 GMT');
      expect(d, isNotNull);
      expect(d!.isUtc, isTrue);
      expect(d.year, 1994);
      expect(d.month, 11);
      expect(d.day, 6);
      expect(d.hour, 8);
      expect(d.minute, 49);
      expect(d.second, 37);
    });

    test('parses RFC 850 two-digit year', () {
      final d = parseHttpDate('Sunday, 06-Nov-94 08:49:37 GMT');
      expect(d, isNotNull);
      expect(d!.year, 1994);
      expect(d.month, 11);
      expect(d.day, 6);
    });

    test('parses asctime format', () {
      final d = parseHttpDate('Sun Nov  6 08:49:37 1994');
      expect(d, isNotNull);
      expect(d!.year, 1994);
      expect(d.month, 11);
      expect(d.day, 6);
      expect(d.hour, 8);
      expect(d.minute, 49);
      expect(d.second, 37);
    });

    test('accepts UTC zone token in IMF-fixdate', () {
      final d = parseHttpDate('Sun, 06 Nov 1994 08:49:37 UTC');
      expect(d, isNotNull);
      expect(d!.isUtc, isTrue);
    });

    test('returns null on invalid', () {
      final d = parseHttpDate('not a date');
      expect(d, isNull);
    });

    test('returns null for ISO-8601 without explicit timezone', () {
      final d = parseHttpDate('2026-04-13T10:00:00');
      expect(d, isNull);
    });
  });
}
