// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:collection';
import 'dart:typed_data';

import 'package:dartssh/socket_html.dart'
    if (dart.library.io) 'package:dartssh/socket_io.dart';

/// Interface for connections, e.g. Socket or WebSocket.
abstract class ConnectionInterface {
  void listen(Function messageHandler);
  void handleError(Function errorHandler);
  void handleDone(Function doneHandler);
  void close();
}

/// Websocket style interface for BSD sockets and/or RFC6455 WebSockets.
abstract class SocketInterface extends ConnectionInterface {
  void connect(Uri uri, Function onConnected, Function onError,
      {int timeoutSeconds = 15, bool ignoreBadCert = false});
  void send(String text);
  void sendRaw(Uint8List raw);
}

/// Mixin for testing with shim [ConnectionInterface]s.
mixin TestConnection {
  bool connected = false, closed = false;
  Function messageHandler, errorHandler, doneHandler;
  Queue<String> sent = Queue<String>();

  void close() => closed = true;
  void handleError(Function errorHandler) => this.errorHandler = errorHandler;
  void handleDone(Function doneHandler) => this.doneHandler = doneHandler;
  void listen(Function messageHandler) => this.messageHandler = messageHandler;
}

/// Shim [Socket] for testing
class TestSocket extends SocketInterface with TestConnection {
  void connect(Uri address, Function onConnected, Function onError,
      {int timeoutSeconds = 15, bool ignoreBadCert = false}) {
    connected = true;
    closed = false;
    onConnected(this);
  }

  void send(String text) => sent.add(text);
  void sendRaw(Uint8List raw) => sent.add(String.fromCharCodes(raw));
}
