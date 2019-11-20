// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:async';
import 'dart:collection';
import 'dart:convert';

import 'package:http/http.dart' as http;

import 'package:dartssh/transport.dart';

/// Asynchronous HTTP request
class HttpRequest {
  String url, method, data;
  Completer<HttpResponse> completer = Completer<HttpResponse>();
  HttpRequest(this.url, this.method, this.data);
}

/// HTTP response integrating [io.HttpClient] and [html.HttpRequest].
class HttpResponse {
  int status;
  String text;
  HttpResponse(this.status, [this.text]);
}

/// HTTP client integrating [io.HttpClient] and [html.HttpRequest].
abstract class HttpClient {
  int numOutstanding = 0;
  StringCallback debugPrint;
  HttpClient([this.debugPrint]);

  Future<HttpResponse> request(String url, {String method, String data});
}

/// Shim [HttpClient] for testing
class TestHttpClient extends HttpClient {
  Queue<HttpRequest> requests = Queue<HttpRequest>();

  @override
  Future<HttpResponse> request(String url, {String method, String data}) {
    HttpRequest httpRequest = HttpRequest(url, method, data);
    requests.add(httpRequest);
    return httpRequest.completer.future;
  }
}

/// package:http based implementation of [HttpClient].
class HttpClientImpl extends HttpClient {
  HttpClientImpl({StringCallback debugPrint, StringFilter userAgent})
      : super(debugPrint);

  @override
  Future<HttpResponse> request(String url, {String method, String data}) async {
    numOutstanding++;
    if (debugPrint != null) debugPrint('HTTP Request: $url');

    http.Client client = http.Client();
    var uriResponse;
    switch (method) {
      case 'POST':
        uriResponse = await client.post(url, body: data);
        break;

      default:
        uriResponse = await client.get(url);
        break;
    }

    HttpResponse ret = HttpResponse(uriResponse.statusCode, uriResponse.body);
    if (debugPrint != null) {
      debugPrint('HTTP Response=${ret.status}: ${ret.text}');
    }
    numOutstanding--;
    return ret;
  }

  void requestWithIncrementalHandler(String url,
      {String method, String data}) async {
    var request = http.Request(method ?? 'GET', Uri.parse(url));
    var response = await request.send();
    var lineStream =
        response.stream.transform(Utf8Decoder()).transform(LineSplitter());

    /// https://github.com/llamadonica/dart-json-stream-parser/tree/master/test
    await for (String line in lineStream) {
      print(line);
    }
  }
}

class UserAgentClient extends http.BaseClient {
  final String userAgent;
  final http.Client _inner;

  UserAgentClient(this.userAgent, this._inner);

  Future<http.StreamedResponse> send(http.BaseRequest request) {
    request.headers['user-agent'] = userAgent;
    return _inner.send(request);
  }
}
