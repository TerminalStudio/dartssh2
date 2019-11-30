// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:async';
import 'dart:html' as html;
import 'dart:typed_data';

import 'package:dartssh/socket.dart';
import 'package:dartssh/transport.dart';

/// dart:html [WebSocket] based implementation of [SocketInterface].
class WebSocketImpl extends SocketInterface {
  static const String type = 'html';

  html.WebSocket socket;
  VoidCallback connectCallback;
  StreamSubscription connectErrorSubscription;

  @override
  void close() => socket.close();

  @override
  void connect(Uri uri, VoidCallback onConnected, StringCallback onError,
      {int timeoutSeconds = 15, bool ignoreBadCert = false}) {
    /// No way to allow self-signed certificates.
    assert(!ignoreBadCert);
    try {
      connectCallback = onConnected;
      socket = html.WebSocket('$uri');
      socket.onOpen.listen(this.onConnected);
      connectErrorSubscription =
          socket.onError.listen((error) => onError('$error'));
    } catch (error) {
      onError('$error');
    }
  }

  void onConnected(dynamic x) {
    connectErrorSubscription.cancel();
    connectErrorSubscription = null;
    connectCallback();
  }

  @override
  void handleError(StringCallback errorHandler) =>
      socket.onError.listen((error) => errorHandler('$error'));

  @override
  void handleDone(StringCallback doneHandler) =>
      socket.onClose.listen((closeEvent) => doneHandler('$closeEvent'));

  @override
  void listen(Uint8ListCallback messageHandler) =>
      socket.onMessage.listen((e) => messageHandler(e.data));

  @override
  void send(String text) => socket.sendString(text);

  @override
  void sendRaw(Uint8List raw) => socket.send(raw);
}
