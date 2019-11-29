// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:collection';
import 'dart:typed_data';

import 'package:dartssh/socket_html.dart'
    if (dart.library.io) 'package:dartssh/socket_io.dart';
import 'package:dartssh/transport.dart';

/// Interface for connections, e.g. Socket or WebSocket.
abstract class ConnectionInterface {
  void listen(Uint8ListCallback messageHandler);
  void handleError(StringCallback errorHandler);
  void handleDone(StringCallback doneHandler);
  void close();
}

/// Websocket style interface for BSD sockets and/or RFC6455 WebSockets.
abstract class SocketInterface extends ConnectionInterface {
  void connect(Uri uri, VoidCallback onConnected, StringCallback onError,
      {int timeoutSeconds = 15, bool ignoreBadCert = false});
  void send(String text);
  void sendRaw(Uint8List raw);
}

/// Mixin for testing with shim [ConnectionInterface]s.
mixin TestConnection {
  bool connected = false, closed = false;
  Uint8ListCallback messageHandler;
  StringCallback errorHandler, doneHandler;
  Queue<String> sent = Queue<String>();

  void close() => closed = true;
  void handleError(StringCallback errorHandler) =>
      this.errorHandler = errorHandler;
  void handleDone(StringCallback doneHandler) => this.doneHandler = doneHandler;
  void listen(Uint8ListCallback messageHandler) =>
      this.messageHandler = messageHandler;
}

/// Shim [Socket] for testing
class TestSocket extends SocketInterface with TestConnection {
  void connect(Uri address, VoidCallback onConnected, StringCallback onError,
      {int timeoutSeconds = 15, bool ignoreBadCert = false}) {
    connected = true;
    closed = false;
    onConnected();
  }

  void send(String text) => sent.add(text);
  void sendRaw(Uint8List raw) => sent.add(String.fromCharCodes(raw));
}
