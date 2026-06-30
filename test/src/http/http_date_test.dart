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

    test('parses ISO-8601 with explicit timezone (Z or offset)', () {
      final d1 = parseHttpDate('2026-04-13T10:00:00Z');
      expect(d1, isNotNull);
      expect(d1!.year, 2026);
      expect(d1.month, 4);
      expect(d1.day, 13);
      expect(d1.hour, 10);
      expect(d1.isUtc, isTrue);

      final d2 = parseHttpDate('2026-04-13T10:00:00+0200');
      expect(d2, isNotNull);
      expect(d2!.year, 2026);
      expect(d2.month, 4);
      expect(d2.day, 13);
      expect(d2.hour, 8); // +0200 converted to UTC is 08:00
      expect(d2.isUtc, isTrue);

      final d3 = parseHttpDate('2026-04-13T10:00:00-05:00');
      expect(d3, isNotNull);
      expect(d3!.year, 2026);
      expect(d3.month, 4);
      expect(d3.day, 13);
      expect(d3.hour, 15); // -0500 converted to UTC is 15:00
      expect(d3.isUtc, isTrue);
    });

    test('parses RFC 850 year boundary pivot', () {
      // yy >= 70 -> 1900 + yy
      final d1 = parseHttpDate('Sunday, 06-Nov-70 08:49:37 GMT');
      expect(d1, isNotNull);
      expect(d1!.year, 1970);

      // yy < 70 -> 2000 + yy
      final d2 = parseHttpDate('Sunday, 06-Nov-69 08:49:37 GMT');
      expect(d2, isNotNull);
      expect(d2!.year, 2069);
    });

    test('case insensitive month names', () {
      final d1 = parseHttpDate('Sun, 06 nov 1994 08:49:37 GMT');
      expect(d1, isNotNull);
      expect(d1!.month, 11);

      final d2 = parseHttpDate('Sun, 06 NoV 1994 08:49:37 GMT');
      expect(d2, isNotNull);
      expect(d2!.month, 11);

      final d3 = parseHttpDate('Sun, 06 XYZ 1994 08:49:37 GMT');
      expect(d3, isNull);
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
