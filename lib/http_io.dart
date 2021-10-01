// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:async';
import 'dart:convert';
import 'dart:io' as io;

import 'package:dartssh/http.dart';
import 'package:dartssh/transport.dart';

/// dart:io based alternative [HttpClient] implementation.
class HttpClientImpl extends HttpClient {
  static const String type = 'io';
  io.HttpClient client = io.HttpClient();

  HttpClientImpl({
    StringCallback? debugPrint,
    StringFilter? userAgent,
  }) : super(debugPrint: debugPrint) {
    if (userAgent != null) client.userAgent = userAgent(client.userAgent);
  }

  @override
  Future<HttpResponse> request(
    String url, {
    String? method,
    String? data,
    Map<String, String>? headers,
  }) async {
    numOutstanding++;

    final uri = Uri.parse(url);

    late io.HttpClientRequest request;
    switch (method) {
      case 'POST':
        request = await client.postUrl(uri);
        break;

      default:
        request = await client.getUrl(uri);
        break;
    }

    if (headers != null) {
      headers.forEach(
        (String key, String value) => request.headers.add(key, value),
      );
    }

    debugPrint?.call('HTTP Request: ${request.uri}');
    final response = await request.close();
    final ret = HttpResponse(response.statusCode);
    await for (var contents in response.transform(Utf8Decoder())) {
      if (ret.text == null) {
        ret.text = contents;
      } else {
        ret.text = ret.text! + contents;
      }
    }

    debugPrint?.call('HTTP Response=${ret.status}: ${ret.text}');
    numOutstanding--;
    return ret;
  }
}
