// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:collection';
import 'dart:typed_data';

import 'package:dartssh/socket_html.dart'
    if (dart.library.io) 'package:dartssh/socket_io.dart';
import 'package:dartssh/transport.dart';

enum ConnectionDirection { receive, send, both }

/// Interface for connections, e.g. Socket or WebSocket.
abstract class ConnectionInterface {
  /// Invokes [messageHandler] upon reading input from the connection.
  void listen(Uint8ListCallback messageHandler);

  /// Invokes [errorHandler] if a connection error occurs.
  void handleError(StringCallback errorHandler);

  /// Involes [handleDone] if the connection is closed normally.
  void handleDone(StringCallback doneHandler);

  /// Closed the connection.
  void close();
}

/// Websocket style interface for BSD sockets and/or RFC6455 WebSockets.
abstract class SocketInterface extends ConnectionInterface {
  // True if this socket is connected.
  bool get connected;

  // True if this socket is connecting.
  bool get connecting;

  /// Connects the socket to [uri] then invokes [onConnected] or [onError].
  void connect(Uri uri, VoidCallback onConnected, StringCallback onError,
      {int timeoutSeconds = 15, bool ignoreBadCert = false});

  /// Sends [text] over the socket.
  void send(String text);

  /// Sends [raw] over the socket.
  void sendRaw(Uint8List raw);

  void shutdown(ConnectionDirection direction) {}
}

/// Mixin for testing with shim [ConnectionInterface]s.
mixin TestConnection {
  bool connected = false, connecting = false, closed = false;
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
