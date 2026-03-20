import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/src/http/http_client.dart';
import 'package:dartssh2/src/http/http_exception.dart';
import 'package:dartssh2/src/socket/ssh_socket.dart';
import 'package:test/test.dart';

void main() {
  group('SSHHttpClientResponse.from', () {
    test('parses status line, headers and body', () async {
      final socket = _FakeSocket([
        'HTTP/1.1 200 OK\r\n',
        'content-length: 5\r\n',
        'content-type: text/plain; charset=utf-8\r\n',
        '\r\n',
        'hello',
      ]);

      final response = await SSHHttpClientResponse.from(socket);

      expect(response.statusCode, 200);
      expect(response.reasonPhrase, 'OK');
      expect(response.body, 'hello');
      expect(response.headers.contentLength, 5);
      expect(response.headers.contentType?.mimeType, 'text/plain');
      expect(socket.closed, isTrue);
    });

    test('supports HTTP/1.0 responses', () async {
      final socket = _FakeSocket([
        'HTTP/1.0 404 Not Found\r\n',
        'content-length: 0\r\n',
        '\r\n',
      ]);

      final response = await SSHHttpClientResponse.from(socket);

      expect(response.statusCode, 404);
      expect(response.reasonPhrase, 'Not Found');
      expect(response.body, isEmpty);
    });

    test('throws for non-identity transfer encoding', () async {
      final socket = _FakeSocket([
        'HTTP/1.1 200 OK\r\n',
        'transfer-encoding: chunked\r\n',
        'content-length: 0\r\n',
        '\r\n',
      ]);

      await expectLater(
        SSHHttpClientResponse.from(socket),
        throwsA(isA<UnsupportedError>()),
      );
    });

    test('throws for unsupported response format', () async {
      final socket = _FakeSocket([
        'NOT_HTTP\r\n',
      ]);

      await expectLater(
        SSHHttpClientResponse.from(socket),
        throwsA(isA<UnsupportedError>()),
      );
    });
  });

  group('SSHHttpClientResponse headers', () {
    test('throws when reading duplicated header via value()', () async {
      final socket = _FakeSocket([
        'HTTP/1.1 200 OK\r\n',
        'x-test: a\r\n',
        'x-test: b\r\n',
        'content-length: 0\r\n',
        '\r\n',
      ]);

      final response = await SSHHttpClientResponse.from(socket);

      expect(
        () => response.headers.value('x-test'),
        throwsA(isA<SSHHttpException>()),
      );
    });

    test('parses date-like headers and exposes raw host header', () async {
      final socket = _FakeSocket([
        'HTTP/1.1 200 OK\r\n',
        'host: localhost:8080\r\n',
        'date: 2024-01-01T10:00:00.000Z\r\n',
        'expires: 2024-01-01T12:00:00.000Z\r\n',
        'if-modified-since: 2024-01-01T09:00:00.000Z\r\n',
        'content-length: 0\r\n',
        '\r\n',
      ]);

      final response = await SSHHttpClientResponse.from(socket);

      expect(response.headers.value('host'), 'localhost:8080');
      expect(response.headers.date, DateTime.parse('2024-01-01T10:00:00.000Z'));
      expect(
          response.headers.expires, DateTime.parse('2024-01-01T12:00:00.000Z'));
      expect(
        response.headers.ifModifiedSince,
        DateTime.parse('2024-01-01T09:00:00.000Z'),
      );
    });

    test('response headers are immutable', () async {
      final socket = _FakeSocket([
        'HTTP/1.1 200 OK\r\n',
        'content-length: 0\r\n',
        '\r\n',
      ]);

      final response = await SSHHttpClientResponse.from(socket);

      expect(
        () => response.headers.add('x', '1'),
        throwsA(isA<UnsupportedError>()),
      );
      expect(
        () => response.headers.set('x', '1'),
        throwsA(isA<UnsupportedError>()),
      );
      expect(
        () => response.headers.removeAll('x'),
        throwsA(isA<UnsupportedError>()),
      );
      expect(
        () => response.headers.clear(),
        throwsA(isA<UnsupportedError>()),
      );
    });
  });
}

class _FakeSocket implements SSHSocket {
  _FakeSocket(List<String> chunks)
      : _chunks = chunks
            .map((chunk) => Uint8List.fromList(chunk.codeUnits))
            .toList(growable: false);

  final List<Uint8List> _chunks;
  final _sinkController = StreamController<List<int>>();
  final _doneCompleter = Completer<void>();
  bool closed = false;

  @override
  Stream<Uint8List> get stream => Stream<Uint8List>.fromIterable(_chunks);

  @override
  StreamSink<List<int>> get sink => _sinkController.sink;

  @override
  Future<void> get done => _doneCompleter.future;

  @override
  Future<void> close() async {
    closed = true;
    if (!_doneCompleter.isCompleted) {
      _doneCompleter.complete();
    }
    await _sinkController.close();
  }

  @override
  void destroy() {
    closed = true;
    if (!_doneCompleter.isCompleted) {
      _doneCompleter.complete();
    }
    unawaited(_sinkController.close());
  }
}
