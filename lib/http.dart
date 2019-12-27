// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import 'package:dartssh/client.dart';
import 'package:dartssh/serializable.dart';
import 'package:dartssh/socket.dart';
import 'package:dartssh/transport.dart';

typedef HttpClientFactory = http.Client Function();
typedef SocketFilter = Future<SocketInterface> Function(SocketInterface);

/// Asynchronous HTTP request
class HttpRequest {
  String url, method, data;
  Map<String, String> headers;
  Completer<HttpResponse> completer = Completer<HttpResponse>();
  HttpRequest(this.url, this.method, {this.data, this.headers});
}

/// HTTP response integrating [io.HttpClient] and [html.HttpRequest].
class HttpResponse {
  int status, contentLength;
  String text, reason;
  Map<String, String> headers;
  Stream<List<int>> contentStream;
  HttpResponse(this.status,
      {this.text,
      this.reason,
      this.headers,
      this.contentStream,
      this.contentLength});
}

/// HTTP client integrating [io.HttpClient] and [html.HttpRequest].
abstract class HttpClient {
  int numOutstanding = 0;
  StringCallback debugPrint;
  HttpClient({this.debugPrint});

  Future<HttpResponse> request(String url,
      {String method, String data, Map<String, String> headers});
}

/// Shim [HttpClient] for testing
class TestHttpClient extends HttpClient {
  Queue<HttpRequest> requests = Queue<HttpRequest>();

  @override
  Future<HttpResponse> request(String url,
      {String method, String data, Map<String, String> headers}) {
    HttpRequest httpRequest = HttpRequest(url, method, data: data);
    requests.add(httpRequest);
    return httpRequest.completer.future;
  }
}

/// package:http based implementation of [HttpClient].
class HttpClientImpl extends HttpClient {
  HttpClientFactory clientFactory;
  HttpClientImpl(
      {this.clientFactory, StringCallback debugPrint, StringFilter userAgent})
      : super(debugPrint: debugPrint) {
    clientFactory ??= () => UserAgentBaseClient(
        userAgent == null ? null : userAgent('HttpClientImpl'), http.Client());
  }

  @override
  Future<HttpResponse> request(String url,
      {String method, String data, Map<String, String> headers}) async {
    numOutstanding++;
    if (debugPrint != null) debugPrint('HTTP Request: $url');

    http.Client client = clientFactory();
    var uriResponse;
    switch (method) {
      case 'POST':
        uriResponse = await client.post(url, body: data, headers: headers);
        break;

      default:
        uriResponse = await client.get(url, headers: headers);
        break;
    }

    HttpResponse ret =
        HttpResponse(uriResponse.statusCode, text: uriResponse.body);
    if (debugPrint != null) {
      debugPrint('HTTP Response=${ret.status}: ${ret.text}');
    }
    numOutstanding--;
    return ret;
  }

  /*void requestWithIncrementalHandler(String url,
      {String method, String data}) async {
    var request = http.Request(method ?? 'GET', Uri.parse(url));
    var response = await request.send();
    var lineStream =
        response.stream.transform(Utf8Decoder()).transform(LineSplitter());

    /// https://github.com/llamadonica/dart-json-stream-parser/tree/master/test
    await for (String line in lineStream) {
      print(line);
    }
  }*/
}

/// [http.BaseClient] with [userAgent] header.
/// Reference: https://github.com/dart-lang/http/blob/master/README.md
class UserAgentBaseClient extends http.BaseClient {
  final String userAgent;
  final http.Client inner;
  UserAgentBaseClient(this.userAgent, this.inner);

  Future<http.StreamedResponse> send(http.BaseRequest request) {
    if (userAgent != null) {
      request.headers['user-agent'] = userAgent;
    }
    return inner.send(request);
  }
}

/// [http.BaseClient] running over [SSHTunneledSocketImpl].
class SSHTunneledBaseClient extends http.BaseClient {
  final String userAgent;
  final SSHClient client;
  SSHTunneledBaseClient(this.client, {this.userAgent});

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    if (userAgent != null) {
      request.headers['user-agent'] = userAgent;
    }

    HttpResponse response = await httpRequest(
      request.url,
      request.method,
      SSHTunneledSocketImpl.fromClient(client),
      requestHeaders: request.headers,
      body: await request.finalize().toBytes(),
      debugPrint: client.debugPrint,
      persistentConnection: request.persistentConnection,
    );

    return http.StreamedResponse(
      response.contentStream,
      response.status,
      contentLength: response.contentLength,
      request: request,
      headers: response.headers,
      reasonPhrase: response.reason,
    );
  }
}

/// In basic HTTP authentication, a request contains a header field in the form of
/// Authorization: Basic <credentials>, where credentials is the base64 encoding of id
/// and password joined by a single colon.
/// https://en.wikipedia.org/wiki/Basic_access_authentication
Map<String, String> addBasicAuthenticationHeader(
    Map<String, String> headers, String username, String password) {
  headers['authorization'] =
      'Basic ' + base64.encode(utf8.encode('$username:$password'));
  return headers;
}

Future<SocketInterface> connectUri(Uri uri, SocketInterface socket,
    {SocketFilter secureUpgrade}) async {
  /// We might be asking the remote to open an SSH tunnel to [uri].
  Completer<String> connectCompleter = Completer<String>();
  socket.connect(uri, () => connectCompleter.complete(null),
      (error) => connectCompleter.complete('$error'));
  String connectError = await connectCompleter.future;
  if (connectError != null) throw FormatException(connectError);

  if (secureUpgrade != null &&
      uri.hasScheme &&
      (uri.scheme == 'https' || uri.scheme == 'wss')) {
    socket = await secureUpgrade(socket);
  }

  return socket;
}

/// Makes HTTP request over [SocketInterface], e.g. [SSHTunneledSocketImpl].
Future<HttpResponse> httpRequest(Uri uri, String method, SocketInterface socket,
    {Map<String, String> requestHeaders,
    Uint8List body,
    StringCallback debugPrint,
    bool persistentConnection = true}) async {
  /// Initialize connection state.
  String headerText;
  List<String> statusLine;
  Map<String, String> headers;
  int contentLength = 0, contentRead = 0;
  QueueBuffer buffer = QueueBuffer(Uint8List(0));
  Completer<String> readHeadersCompleter = Completer<String>();
  StreamController<List<int>> contentController = StreamController<List<int>>();

  if (!socket.connected && !socket.connecting) {
    socket = await connectUri(uri, socket);
  }
  socket.handleDone((String reason) {
    if (debugPrint != null) {
      debugPrint('SSHTunneledBaseClient.socket.handleDone');
    }
    socket.close();
    contentController.close();
    if (headerText == null) readHeadersCompleter.complete('done');
  });

  socket.handleError((error) {
    if (debugPrint != null) {
      debugPrint('SSHTunneledBaseClient.socket.handleError');
    }
    socket.close();
    contentController.close();
    if (headerText == null) readHeadersCompleter.complete('$error');
  });

  socket.listen((Uint8List m) {
    if (debugPrint != null) {
      debugPrint('SSHTunneledBaseClient.socket.listen: read ${m.length} bytes');
    }
    if (headerText == null) {
      buffer.add(m);
      int headersEnd = searchUint8List(
          buffer.data, Uint8List.fromList('\r\n\r\n'.codeUnits));

      /// Parse HTTP headers.
      if (headersEnd != -1) {
        headerText = utf8.decode(viewUint8List(buffer.data, 0, headersEnd));
        buffer.flush(headersEnd + 4);
        var lines = LineSplitter.split(headerText);
        statusLine = lines.first.split(' ');
        headers = Map<String, String>.fromIterable(lines.skip(1),
            key: (h) => h.substring(0, h.indexOf(': ')),
            value: (h) => h.substring(h.indexOf(': ') + 2).trim());
        headers.forEach((key, value) {
          if (key.toLowerCase() == 'content-length') {
            contentLength = int.parse(value);
          }
        });
        readHeadersCompleter.complete(null);

        /// If there's no content then we're already done.
        if (contentLength == 0) {
          if (debugPrint != null) {
            debugPrint(
                'SSHTunneledBaseClient.socket.listen: Content-Length: 0, remaining=${buffer.data.length}');
          }
          contentController.close();
          if (!persistentConnection) {
            socket.close();
          }
          return;
        }

        /// Handle any remaining data in the read buffer.
        if (buffer.data.isEmpty) return;
        m = buffer.data;
      }
    }

    /// Add content to the stream until completed.
    contentController.add(m);
    contentRead += m.length;
    if (contentRead >= contentLength) {
      if (debugPrint != null) {
        debugPrint(
            'SSHTunneledBaseClient.socket.listen: done $contentRead / $contentLength');
      }
      contentController.close();
      if (!persistentConnection || contentRead > contentLength) {
        socket.close();
      }
    }
  });

  requestHeaders['Host'] = '${uri.host}';
  if (method == 'POST') {
    requestHeaders['Content-Length'] = '${body.length}';
  }
  socket.send('${method} /${uri.path} HTTP/1.1\r\n' +
      requestHeaders.entries
          .map((header) => '${header.key}: ${header.value}')
          .join('\r\n') +
      '\r\n\r\n');
  if (method == 'POST') socket.sendRaw(body);

  String readHeadersError = await readHeadersCompleter.future;
  if (readHeadersError != null) throw FormatException(readHeadersError);

  return HttpResponse(int.parse(statusLine[1]),
      reason: statusLine.sublist(2).join(' '),
      headers: headers,
      contentLength: contentLength,
      contentStream: contentController.stream);
}
