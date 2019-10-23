// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:io';
import 'dart:typed_data';

import 'package:dartssh/socket.dart';

class SocketImpl extends SocketInterface {
  Socket socket;
  Function onError, onDone;

  @override
  void close() {
    if (socket != null) {
      socket.close();
      socket = null;
    }
  }

  @override
  void connect(String address, Function onConnected, Function onError,
      {int timeoutSeconds = 15}) {
    assert(socket == null);
    Uri uri = Uri.parse(address);
    Socket.connect(uri.host, uri.port,
            timeout: Duration(seconds: timeoutSeconds))
        .then(
            (Socket x) => x == null ? onError(null) : onConnected(socket = x));
  }

  @override
  void handleError(Function errorHandler) => onError = errorHandler;

  @override
  void handleDone(Function doneHandler) => onDone = doneHandler;

  @override
  void listen(Function messageHandler) => socket.listen(messageHandler,
      onDone: onDone != null ? () => onDone(null) : null, onError: onError);

  @override
  void send(String text) => sendRaw(Uint8List.fromList(text.codeUnits));

  @override
  void sendRaw(Uint8List raw) => socket.add(raw);
}
