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
  Uint8ListCallback messageHandler;
  StringCallback errorHandler, doneHandler;
  VoidCallback connectCallback;
  StreamSubscription connectErrorSubscription;

  @override
  void close() {
    messageHandler = null;
    errorHandler = null;
    doneHandler = null;
    if (socket != null) {
      socket.close();
      socket == null;
    }
  }

  @override
  void connect(Uri uri, VoidCallback onConnected, StringCallback onError,
      {int timeoutSeconds = 15, bool ignoreBadCert = false}) {
    /// No way to allow self-signed certificates.
    assert(!ignoreBadCert);
    try {
      connectCallback = onConnected;
      socket = html.WebSocket('$uri');
      socket.onOpen.listen(connectSucceeded);
      connectErrorSubscription =
          socket.onError.listen((error) => onError('$error'));
    } catch (error) {
      onError('$error');
    }
  }

  void connectSucceeded(dynamic x) {
    connectErrorSubscription.cancel();
    connectErrorSubscription = null;

    socket.onError.listen((error) {
      if (errorHandler != null) {
        errorHandler('$error');
      }
    });

    socket.onClose.listen((closeEvent) {
      if (doneHandler != null) {
        doneHandler('$closeEvent');
      }
    });

    socket.onMessage.listen((e) {
      if (messageHandler != null) {
        messageHandler(e.data);
      }
    });

    connectCallback();
  }

  @override
  void handleError(StringCallback newErrorHandler) =>
      errorHandler = newErrorHandler;

  @override
  void handleDone(StringCallback newDoneHandler) =>
      doneHandler = newDoneHandler;

  @override
  void listen(Uint8ListCallback newMessageHandler) =>
      messageHandler = newMessageHandler;

  @override
  void send(String text) => socket.sendString(text);

  @override
  void sendRaw(Uint8List raw) => socket.send(raw);
}
