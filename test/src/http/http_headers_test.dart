import 'package:test/test.dart';

import '../mocks/mock_ssh_http_headers.dart';

void main() {
  group('SSHHttpHeaders', () {
    late MockSSHHttpHeaders headers;

    setUp(() {
      headers = MockSSHHttpHeaders();
    });

    test('should add and retrieve headers correctly', () {
      headers.add('Content-Type', 'application/json');
      expect(headers['content-type'], equals(['application/json']));
    });

    test('should set headers correctly, replacing existing values', () {
      headers.add('Content-Type', 'text/plain');
      headers.set('Content-Type', 'application/json');
      expect(headers['content-type'], equals(['application/json']));
    });

    test('should retrieve the correct single value for a header', () {
      headers.set('Content-Length', 100);
      expect(headers.value('Content-Length'), equals('100'));
    });

    test('should remove a specific header value', () {
      headers.add('Cache-Control', 'no-cache');
      headers.add('Cache-Control', 'no-store');
      headers.remove('Cache-Control', 'no-cache');
      expect(headers['cache-control'], equals(['no-store']));
    });

    test('should remove all values for a header', () {
      headers.add('Cache-Control', 'no-cache');
      headers.removeAll('Cache-Control');
      expect(headers['cache-control'], isNull);
    });

    test('should perform action on each header correctly', () {
      headers.set('Content-Type', 'application/json');
      headers.set('Accept', 'text/html');
      final collectedHeaders = <String, List<String>>{};
      headers.forEach((name, values) {
        collectedHeaders[name] = values;
      });
      expect(collectedHeaders['content-type'], equals(['application/json']));
      expect(collectedHeaders['accept'], equals(['text/html']));
    });

    test('should clear all headers', () {
      headers.set('Content-Type', 'application/json');
      headers.clear();
      expect(headers['content-type'], isNull);
    });

    // Agrega más pruebas según los métodos y comportamientos específicos que quieras verificar
  });
}
