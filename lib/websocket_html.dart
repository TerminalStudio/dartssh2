// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:async';
import 'dart:convert';
import 'dart:html' as html;
import 'dart:typed_data';

import 'package:dartssh/socket.dart';

/// dart:html [WebSocket] implementation.
class WebSocketImpl extends SocketInterface {
  static const String type = 'html';

  html.WebSocket socket;
  Function connectCallback;
  StreamSubscription connectErrorSubscription;

  @override
  void close() => socket.close();

  @override
  void connect(Uri uri, Function onConnected, Function onError,
      {int timeoutSeconds = 15, bool ignoreBadCert = false}) {
    /// No way to allow self-signed certificates.
    assert(!ignoreBadCert);
    try {
      connectCallback = onConnected;
      socket = html.WebSocket('$uri');
      socket.onOpen.listen(this.onConnected);
      connectErrorSubscription = socket.onError.listen(onError);
    } catch (error) {
      onError(error, null);
    }
  }

  void onConnected(dynamic x) {
    connectErrorSubscription.cancel();
    connectErrorSubscription = null;
    connectCallback(x);
  }

  @override
  void handleError(Function errorHandler) =>
      socket.onError.listen(errorHandler);

  @override
  void handleDone(Function doneHandler) => socket.onClose.listen(doneHandler);

  @override
  void listen(Function messageHandler) =>
      socket.onMessage.listen((e) => messageHandler(utf8.encode(e.data)));

  @override
  void send(String text) => socket.sendString(text);

  @override
  void sendRaw(Uint8List raw) => socket.send(raw);
}
