import 'package:dartssh2/dartssh2.dart';
import 'package:test/test.dart';

void main() {
  group('SSHContentType', () {
    test('should return predefined text content type', () {
      final contentType = SSHContentType.text;

      expect(contentType.primaryType, equals('text'));
      expect(contentType.subType, equals('plain'));
      expect(contentType.charset, equals('utf-8'));
    });

    test('should return predefined html content type', () {
      final contentType = SSHContentType.html;

      expect(contentType.primaryType, equals('text'));
      expect(contentType.subType, equals('html'));
      expect(contentType.charset, equals('utf-8'));
    });

    test('should return predefined json content type', () {
      final contentType = SSHContentType.json;

      expect(contentType.primaryType, equals('application'));
      expect(contentType.subType, equals('json'));
      expect(contentType.charset, equals('utf-8'));
    });

    test('should return predefined binary content type', () {
      final contentType = SSHContentType.binary;

      expect(contentType.primaryType, equals('application'));
      expect(contentType.subType, equals('octet-stream'));
      expect(contentType.charset, isNull);
    });

    test('should create content type with charset', () {
      final contentType = SSHContentType(
        'application',
        'xml',
        charset: 'ISO-8859-1',
      );

      expect(contentType.primaryType, equals('application'));
      expect(contentType.subType, equals('xml'));
      expect(contentType.charset, equals('iso-8859-1'));
    });

    test('should parse content type string without parameters', () {
      final contentType = SSHContentType.parse('text/html');

      expect(contentType.primaryType, equals('text'));
      expect(contentType.subType, equals('html'));
      expect(contentType.charset, isNull);
    });

    test('should parse content type string with charset', () {
      final contentType = SSHContentType.parse('text/html; charset=utf-8');

      expect(contentType.primaryType, equals('text'));
      expect(contentType.subType, equals('html'));
      expect(contentType.charset, equals('utf-8'));
    });

    test('should parse content type string with additional parameters', () {
      final contentType = SSHContentType.parse(
          'application/json; charset=utf-8; custom-param=value');

      expect(contentType.primaryType, equals('application'));
      expect(contentType.subType, equals('json'));
      expect(contentType.charset, equals('utf-8'));
    });

    test('should handle invalid content type strings gracefully', () {
      expect(SSHContentType.parse('invalid/type'), isA<SSHContentType>());
      expect(SSHContentType.parse('text/html;charset=utf-8;invalid'),
          isA<SSHContentType>());
    });
  });
}
