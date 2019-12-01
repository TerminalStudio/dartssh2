// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dartssh/client.dart';
import 'package:dartssh/socket.dart';
import 'package:dartssh/transport.dart';

/// dart:io [Socket] based implementation of [SocketInterface].
class SocketImpl extends SocketInterface {
  Socket socket;
  StringCallback onError, onDone;
  SocketImpl([this.socket]);

  @override
  void close() {
    if (socket != null) {
      socket.close();
      socket = null;
    }
  }

  @override
  void connect(Uri uri, VoidCallback onConnected, StringCallback onError,
      {int timeoutSeconds = 15, bool ignoreBadCert = false}) {
    if (socket != null) {
      if (socket is SSHTunneledSocket) {
        SSHTunneledSocket tunneledSocket = socket;
        tunneledSocket.impl.connect(uri, onConnected, onError,
            timeoutSeconds: timeoutSeconds, ignoreBadCert: ignoreBadCert);
      } else {
        throw FormatException();
      }
    } else {
      Socket.connect(uri.host, uri.port,
              timeout: Duration(seconds: timeoutSeconds))
          .then((Socket x) {
        if (x == null) {
          onError(null);
        } else {
          socket = x;
          onConnected();
        }
      });
    }
  }

  @override
  void handleError(StringCallback errorHandler) => onError = errorHandler;

  @override
  void handleDone(StringCallback doneHandler) => onDone = doneHandler;

  @override
  void listen(Uint8ListCallback messageHandler) => socket.listen(messageHandler,
      onDone: onDone == null ? null : () => onDone(null),
      onError: onError == null
          ? null
          : (error, stacktrace) => onError('$error: $stacktrace'));

  @override
  void send(String text) => sendRaw(utf8.encode(text));

  @override
  void sendRaw(Uint8List raw) => socket.add(raw);
}

/// https://github.com/dart-lang/sdk/blob/master/sdk/lib/_internal/vm/bin/socket_patch.dart#L1651
class SSHTunneledSocket extends Stream<Uint8List> implements Socket {
  SSHTunneledSocketImpl impl;
  StreamController<Uint8List> controller;
  SSHTunneledSocketStreamConsumer consumer;
  IOSink sink;

  SSHTunneledSocket(this.impl) {
    controller = StreamController<Uint8List>(sync: true);
    consumer = SSHTunneledSocketStreamConsumer(this);
    sink = IOSink(consumer);
    /// https://github.com/dart-lang/sdk/issues/39589
    impl.listen((Uint8List m) => controller.add(Uint8List.fromList(m)));
    impl.handleError((error) => controller.addError(error));
    impl.handleDone((String reason) => controller.addError(reason));
  }

  @override
  Encoding get encoding => sink.encoding;

  @override
  set encoding(Encoding value) => sink.encoding = value;

  @override
  void add(List<int> bytes) => sink.add(bytes);

  @override
  void write(Object obj) => sink.write(obj);

  @override
  void writeAll(Iterable objects, [String separator = ""]) =>
      sink.writeAll(objects, separator);

  @override
  void writeln([Object obj = ""]) => sink.writeln(obj);

  @override
  void writeCharCode(int charCode) => sink.writeCharCode(charCode);

  @override
  void addError(error, [StackTrace stackTrace]) {
    throw UnsupportedError("Cannot send errors on sockets");
  }

  @override
  Future<Socket> addStream(Stream<List<int>> stream) => sink.addStream(stream);

  @override
  Future flush() => sink.flush();

  @override
  Future close() => sink.close();

  @override
  Future get done => sink.done;

  @override
  void destroy() {
    consumer.stop();
    impl.close();
    controller.close();
  }

  @override
  bool setOption(SocketOption option, bool enabled) => false;

  @override
  Uint8List getRawOption(RawSocketOption option) => null;

  @override
  void setRawOption(RawSocketOption option) {}

  @override
  int get port => impl.sourcePort;

  @override
  int get remotePort => impl.tunnelToPort;

  @override
  InternetAddress get address => InternetAddress(impl.sourceHost);

  @override
  InternetAddress get remoteAddress => InternetAddress(impl.tunnelToHost);

  @override
  StreamSubscription<Uint8List> listen(void onData(Uint8List event),
      {Function onError, void onDone(), bool cancelOnError}) {
    if (impl.client.debugPrint != null) {
      impl.client
          .debugPrint('SSHTunneledSocket.listen $remoteAddress:$remotePort');
    }
    return controller.stream.listen((m) {
      //impl.client.debugPrint('DEBUG SSHTunneledSocket.read $m');
      onData(m);
    }, onError: onError, onDone: onDone, cancelOnError: cancelOnError);
  }
}

/// Copied from https://github.com/dart-lang/sdk/blob/master/sdk/lib/_internal/vm/bin/socket_patch.dart
class SSHTunneledSocketStreamConsumer extends StreamConsumer<List<int>> {
  StreamSubscription subscription;
  final SSHTunneledSocket socket;
  Completer streamCompleter;
  SSHTunneledSocketStreamConsumer(this.socket);

  Future<Socket> addStream(Stream<List<int>> stream) {
    //socket._ensureRawSocketSubscription();
    streamCompleter = Completer<Socket>();
    if (socket.impl != null) {
      subscription = stream.listen((data) {
        try {
          if (subscription != null) {
            assert(data != null);
            socket.impl.sendRaw(data);
          }
        } catch (e) {
          socket.destroy();
          stop();
          done(e);
        }
      }, onError: (error, [stackTrace]) {
        socket.destroy();
        done(error, stackTrace);
      }, onDone: () {
        done();
      }, cancelOnError: true);
    }
    return streamCompleter.future;
  }

  Future<Socket> close() {
    //socket._consumerDone();
    return Future.value(socket);
  }

  void done([error, stackTrace]) {
    if (streamCompleter != null) {
      if (error != null) {
        streamCompleter.completeError(error, stackTrace);
      } else {
        streamCompleter.complete(socket);
      }
      streamCompleter = null;
    }
  }

  void stop() {
    if (subscription == null) return;
    subscription.cancel();
    subscription = null;
    //socket._disableWriteEvent();
  }
}
