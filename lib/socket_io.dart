// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:dartssh/serializable.dart';
import 'package:dartssh/socket.dart';
import 'package:dartssh/transport.dart';

/// dart:io [Socket] based implementation of [SocketInterface].
class SocketImpl extends SocketInterface {
  Socket socket;
  StreamSubscription messageSubscription;
  Uint8ListCallback messageHandler;
  StringCallback onError, onDone;

  @override
  bool get connected => socket != null;

  @override
  bool connecting = false;

  SocketImpl([this.socket]);

  @override
  void close() {
    connecting = false;
    messageHandler = null;
    onError = onDone = null;
    if (messageSubscription != null) {
      messageSubscription.cancel();
      messageSubscription = null;
    }
    if (socket != null) {
      socket.close();
      socket = null;
    }
  }

  @override
  void connect(Uri uri, VoidCallback onConnected, StringCallback onError,
      {int timeoutSeconds = 15, bool ignoreBadCert = false}) {
    assert(!connecting);
    connecting = true;
    if (socket != null) {
      if (socket is SocketAdaptor) {
        (socket as SocketAdaptor).impl.connect(
            uri, () => connectSucceeded(onConnected), onError,
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
          connectSucceeded(onConnected);
        }
      });
    }
  }

  void connectSucceeded(VoidCallback onConnected) {
    connecting = false;
    onConnected();
  }

  @override
  void handleError(StringCallback errorHandler) => onError = errorHandler;

  @override
  void handleDone(StringCallback doneHandler) => onDone = doneHandler;

  @override
  void listen(Uint8ListCallback newMessageHandler) {
    messageHandler = newMessageHandler;
    if (messageSubscription == null) {
      messageSubscription = socket.listen((Uint8List m) {
        if (messageHandler != null) {
          messageHandler(m);
        }
      }, onDone: () {
        if (onDone != null) {
          onDone(null);
        }
      }, onError: (error, stacktrace) {
        if (onError != null) {
          onError('$error: $stacktrace');
        }
      });
    }
  }

  @override
  void send(String text) => sendRaw(utf8.encode(text));

  @override
  void sendRaw(Uint8List raw) => socket.add(raw);
}

/// https://github.com/dart-lang/sdk/blob/master/sdk/lib/_internal/vm/bin/socket_patch.dart#L1651
class SocketAdaptor extends Stream<Uint8List> implements Socket {
  SocketInterface impl;
  StreamController<Uint8List> controller;
  SocketAdaptorStreamConsumer consumer;
  IOSink sink;
  StringCallback debugPrint;
  var _detachReady;

  @override
  InternetAddress address;

  @override
  InternetAddress remoteAddress;

  @override
  int port;

  @override
  int remotePort;

  @override
  Encoding get encoding => sink.encoding;

  @override
  set encoding(Encoding value) => sink.encoding = value;

  SocketAdaptor(this.impl,
      {this.address,
      this.remoteAddress,
      this.port,
      this.remotePort,
      this.debugPrint}) {
    controller = StreamController<Uint8List>(sync: true);
    consumer = SocketAdaptorStreamConsumer(this);
    sink = IOSink(consumer);

    /// https://github.com/dart-lang/sdk/issues/39589
    impl.listen((Uint8List m) => controller.add(Uint8List.fromList(m)));
    impl.handleError((error) => controller.addError(error));
    impl.handleDone((String reason) => controller.addError(reason));
  }

  @override
  void destroy() {
    consumer.stop();
    impl.close();
    controller.close();
  }

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
  bool setOption(SocketOption option, bool enabled) => false;

  @override
  Uint8List getRawOption(RawSocketOption option) => null;

  @override
  void setRawOption(RawSocketOption option) {}

  @override
  StreamSubscription<Uint8List> listen(void onData(Uint8List event),
      {Function onError, void onDone(), bool cancelOnError}) {
    //debugPrint('DEBUG SocketAdaptor.listen $remoteAddress:$remotePort');
    return controller.stream.listen((m) {
      //debugPrint('DEBUG SocketAdaptor.read $m');
      onData(m);
    }, onError: onError, onDone: onDone, cancelOnError: cancelOnError);
  }

  /*void _consumerDone() {
    if (_detachReady != null) {
      _detachReady.complete(null);
    } else {
      if (impl != null) {
        impl.shutdown(ConnectionDirection.send);
      }
    }
  }*/

  /*Future _detachRaw() {
    _detachReady = new Completer();
    sink.close();
    return _detachReady.future.then((_) {
      var raw = impl;
      impl = null;
      return [
        RawSocketAdaptor(raw,
            address: address,
            remoteAddress: remoteAddress,
            port: port,
            remotePort: remotePort,
            debugPrint: debugPrint),
        null
      ];
    });
  }*/
}

/// Copied from https://github.com/dart-lang/sdk/blob/master/sdk/lib/_internal/vm/bin/socket_patch.dart
class SocketAdaptorStreamConsumer extends StreamConsumer<List<int>> {
  final SocketAdaptor socket;
  StreamSubscription subscription;
  Completer streamCompleter;
  SocketAdaptorStreamConsumer(this.socket);

  Future<Socket> close() {
    //socket._consumerDone();
    return Future.value(socket);
  }

  void stop() {
    if (subscription == null) return;
    subscription.cancel();
    subscription = null;
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

  Future<Socket> addStream(Stream<List<int>> stream) {
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
}

/// https://github.com/dart-lang/sdk/blob/master/sdk/lib/_internal/vm/bin/socket_patch.dart#L1651
/*
class RawSocketAdaptor extends Stream<RawSocketEvent> implements RawSocket {
  final SocketInterface socket;
  StreamController<RawSocketEvent> controller;
  QueueBuffer readBuffer = QueueBuffer(Uint8List(0));
  StringCallback debugPrint;
  bool _readEventsEnabled = true;
  bool _writeEventsEnabled = true;
  bool _paused = false;

  @override
  InternetAddress address;

  @override
  InternetAddress remoteAddress;

  @override
  int port;

  @override
  int remotePort;

  RawSocketAdaptor(this.socket,
      {this.address,
      this.remoteAddress,
      this.port,
      this.remotePort,
      this.debugPrint}) {
    controller = StreamController(
        sync: true,
        onListen: _onSubscriptionStateChange,
        onCancel: _onSubscriptionStateChange,
        onPause: _onPauseStateChange,
        onResume: _onPauseStateChange);

    socket.listen((Uint8List m) {
      readBuffer.add(m);
      if (!_paused && _readEventsEnabled) {
        controller.add(RawSocketEvent.read);
      }
    });

    socket.handleDone((String reason) {
      controller.add(RawSocketEvent.readClosed);
      //controller.add(RawSocketEvent.closed);
      //controller.close();
    });

    socket.handleError((error) => controller.addError(error));
  }

  @override
  StreamSubscription<RawSocketEvent> listen(void onData(RawSocketEvent event),
      {Function onError, void onDone(), bool cancelOnError}) {
    return controller.stream.listen(onData,
        onError: onError, onDone: onDone, cancelOnError: cancelOnError);
  }

  @override
  int available() => readBuffer.data.length;

  @override
  Uint8List read([int len]) {
    int readSize = len != null ? min(len, available()) : available();
    if (readSize == null) return null;
    Uint8List data = readBuffer.data.sublist(0, readSize);
    readBuffer.flush(readSize);
    return data;
  }

  @override
  int write(List<int> buffer, [int offset, int count]) {
    socket.sendRaw(Uint8List.fromList((offset == null && count == null)
        ? buffer
        : buffer.sublist(offset, offset + count)));
    return count ?? buffer.length;
  }

  @override
  Future<RawSocket> close() {
    socket.close();
    return Future.value(this);
  }

  @override
  void shutdown(SocketDirection direction) {}

  @override
  bool get readEventsEnabled => _readEventsEnabled;

  @override
  set readEventsEnabled(bool value) {
    if (value != _readEventsEnabled) {
      _readEventsEnabled = value;
      if (!controller.isPaused) _resume();
    }
  }

  @override
  bool get writeEventsEnabled => _writeEventsEnabled;

  @override
  set writeEventsEnabled(bool value) {
    if (value != _writeEventsEnabled) {
      _writeEventsEnabled = value;
      if (!controller.isPaused) _resume();
    }
  }

  @override
  bool setOption(SocketOption option, bool enabled) => false;

  @override
  Uint8List getRawOption(RawSocketOption option) => null;

  @override
  void setRawOption(RawSocketOption option) {}

  void _onPauseStateChange() {
    if (controller.isPaused) {
      _pause();
    } else {
      _resume();
    }
  }

  void _onSubscriptionStateChange() {
    if (controller.hasListener) {
      _resume();
    } else {
      socket.close();
    }
  }

  void _pause() => _paused = true;
  void _resume() => _paused = false;
}
*/

InternetAddress tryParseInternetAddress(String x) {
  try {
    return InternetAddress(x);
  } catch (error) {
    return null;
  }
}
