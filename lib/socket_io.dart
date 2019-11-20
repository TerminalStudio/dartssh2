// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dartssh/client.dart';
import 'package:dartssh/socket.dart';

/// dart:io [Socket] based implementation of [SocketInterface].
class SocketImpl extends SocketInterface {
  Socket socket;
  Function onError, onDone;
  SocketImpl([this.socket]);

  @override
  void close() {
    if (socket != null) {
      socket.close();
      socket = null;
    }
  }

  @override
  void connect(Uri uri, Function onConnected, Function onError,
      {int timeoutSeconds = 15, bool ignoreBadCert = false}) {
    if (socket != null) throw FormatException();
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

/// https://github.com/dart-lang/sdk/blob/master/sdk/lib/_internal/vm/bin/socket_patch.dart#L1651
class SSHTunneledSocket extends Stream<Uint8List> implements Socket {
  StreamController<Uint8List> controller;
  SSHTunneledSocketImpl impl;
  SSHTunneledSocket(this.impl);

  @override
  Encoding encoding;

  @override
  void add(List<int> bytes) => impl.sendRaw(Uint8List.fromList(bytes));

  @override
  void write(Object obj) => add(obj.toString().codeUnits);

  @override
  void writeAll(Iterable objects, [String separator = ""]) {
    bool wroteObject = false;
    for (var object in objects) {
      if (wroteObject && separator.isNotEmpty) write(separator);
      write(object);
    }
  }

  @override
  void writeln([Object obj = ""]) => write(obj.toString() + '\n');

  @override
  void writeCharCode(int charCode) => add(<int>[charCode]);

  @override
  void addError(error, [StackTrace stackTrace]) => null;

  @override
  Future addStream(Stream<List<int>> stream) async => null;

  @override
  Future flush() async {}

  @override
  Future close() async => impl.close();

  @override
  Future get done async => impl == null;

  @override
  void destroy() => close();

  @override
  bool setOption(SocketOption option, bool enabled) => false;

  @override
  Uint8List getRawOption(RawSocketOption option) => null;

  @override
  void setRawOption(RawSocketOption option) {}

  @override
  int get port => null;

  @override
  int get remotePort => null;

  @override
  InternetAddress get address => null;

  @override
  InternetAddress get remoteAddress => null;

  @override
  StreamSubscription<Uint8List> listen(void onData(Uint8List event),
      {Function onError, void onDone(), bool cancelOnError}) {
    if (controller == null) {
      controller = StreamController<Uint8List>();
      impl.listen((Uint8List m) => controller.add(m));
      impl.handleError((error) => controller.addError(error));
      if (onDone != null) impl.handleDone(onDone);
    }
    return controller.stream.listen(onData,
        onError: onError, onDone: onDone, cancelOnError: cancelOnError);
  }
}
