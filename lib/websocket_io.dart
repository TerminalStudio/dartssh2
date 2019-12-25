// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:async';
import 'dart:convert';
import 'dart:io' as io;
import 'dart:math';
import 'dart:typed_data';

import 'package:dartssh/client.dart';
import 'package:dartssh/http.dart';
import 'package:dartssh/protocol.dart';
import 'package:dartssh/socket.dart';
import 'package:dartssh/socket_io.dart';
import 'package:dartssh/transport.dart';

/// dart:io [WebSocket] based implementation of [SocketInterface].
class WebSocketImpl extends SocketInterface {
  static const String type = 'io';

  io.WebSocket socket;
  StreamSubscription messageSubscription;
  Uint8ListCallback messageHandler;
  StringCallback errorHandler, doneHandler;

  @override
  bool get connected => socket != null;

  @override
  bool connecting = false;

  @override
  void close() {
    connecting = false;
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
      {int timeoutSeconds = 15, bool ignoreBadCert = false}) async {
    assert(!connecting);
    connecting = true;

    if (!ignoreBadCert || !uri.hasScheme || uri.scheme != 'wss') {
      return io.WebSocket.connect('$uri')
          .timeout(Duration(seconds: timeoutSeconds))
          .then((io.WebSocket x) {
        socket = x;
        connectSucceeded(onConnected);
      }, onError: (error, _) => onError(error));
    }

    io.HttpClient client = io.HttpClient();
    client.badCertificateCallback =
        (io.X509Certificate cert, String host, int port) => true;

    /// Upgrade https to wss using [badCertificateCallback] to allow
    /// self-signed certificates.  This still gains you stream encryption.
    try {
      io.HttpClientRequest request =
          await client.getUrl(Uri.parse('https' + '$uri'.substring(3)));
      request.headers.add('Connection', 'upgrade');
      request.headers.add('Upgrade', 'websocket');
      request.headers.add('sec-websocket-version', '13');
      request.headers.add(
          'sec-websocket-key', base64.encode(randBytes(Random.secure(), 8)));

      io.HttpClientResponse response = await request.close()
        ..timeout(Duration(seconds: timeoutSeconds));

      socket = io.WebSocket.fromUpgradedSocket(await response.detachSocket(),
          serverSide: false);
      connectSucceeded(onConnected);
    } catch (error) {
      onError(error);
    }
  }

  void connectSucceeded(VoidCallback onConnected) {
    connecting = false;
    onConnected();
  }

  @override
  void handleError(StringCallback newErrorHandler) =>
      errorHandler = newErrorHandler;

  @override
  void handleDone(StringCallback newDoneHandler) =>
      doneHandler = newDoneHandler;

  @override
  void listen(Uint8ListCallback newMessageHandler) {
    messageHandler = newMessageHandler;

    if (messageSubscription == null) {
      messageSubscription = socket.listen((m) {
        //print("WebSocketImpl.read: $m");
        if (messageHandler != null) {
          messageHandler(utf8.encode(m));
        }
      });

      socket.done.then((_) {
        if (doneHandler != null) {
          doneHandler(
              'WebSocketImpl.handleDone: ${socket.closeCode} ${socket.closeReason}');
        }
        return null;
      });

      socket.handleError((error, _) {
        if (errorHandler != null) {
          errorHandler(error);
        }
      });
    }
  }

  @override
  void send(String text) => socket.addUtf8Text(utf8.encode(text));

  @override
  void sendRaw(Uint8List raw) => socket.add(raw);
}

/// The initial [SSHTunneledSocketImpl] (which implements same [SocketInteface]
/// as [SSHTunneledWebSocketImpl]), is bridged via [SSHTunneledSocket] adaptor
/// to initialize [io.WebSocket.fromUpgradedSocket()].
class SSHTunneledWebSocketImpl extends WebSocketImpl {
  SocketInterface tunneledSocket;
  final String sourceHost, tunnelToHost;
  final int sourcePort, tunnelToPort;
  final StringCallback debugPrint;

  SSHTunneledWebSocketImpl(SSHTunneledSocketImpl inputSocket)
      : tunneledSocket = inputSocket,
        sourceHost = inputSocket.sourceHost,
        tunnelToHost = inputSocket.tunnelToHost,
        sourcePort = inputSocket.sourcePort,
        tunnelToPort = inputSocket.tunnelToPort,
        debugPrint = inputSocket.client.debugPrint;

  @override
  void connect(Uri uri, VoidCallback onConnected, StringCallback onError,
      {int timeoutSeconds = 15, bool ignoreBadCert = false}) async {
    uri = '$uri'.startsWith('wss')
        ? Uri.parse('https' + '$uri'.substring(3))
        : Uri.parse('http' + '$uri'.substring(2));

    if (!tunneledSocket.connected && !tunneledSocket.connecting) {
      tunneledSocket = await connectUri(uri, tunneledSocket,
          secureUpgrade: (SocketInterface x) async =>
              SocketImpl(await io.SecureSocket.secure(
                SocketAdaptor(x),

                /// https://github.com/dart-lang/sdk/issues/39690
                /*io.Socket.fromRaw(RawSocketAdaptor(
                  x,
                  address: tryParseInternetAddress('127.0.0.1'),
                  remoteAddress: (await io.InternetAddress.lookup(uri.host)).first,
                  port: 1234,
                  remotePort: uri.port,
                  debugPrint: debugPrint,
                )),*/
                onBadCertificate: (io.X509Certificate certificate) =>
                    ignoreBadCert,
              )));
    }

    HttpResponse response = await httpRequest(
      uri,
      'GET',
      tunneledSocket,
      requestHeaders: <String, String>{
        'Connection': 'upgrade',
        'Upgrade': 'websocket',
        'sec-websocket-version': '13',
        'sec-websocket-key': base64.encode(randBytes(Random.secure(), 8))
      },
      debugPrint: debugPrint,
    );
    if (response.status == 101) {
      socket = io.WebSocket.fromUpgradedSocket(
          SocketAdaptor(
            tunneledSocket,
            address: tryParseInternetAddress('127.0.0.1'),
            remoteAddress: (await io.InternetAddress.lookup(uri.host)).first,
            port: 1234,
            remotePort: uri.port,
            debugPrint: debugPrint,
          ),

          /// https://github.com/dart-lang/sdk/issues/39690
          /*io.Socket.socketFromRaw(RawSocketAdaptor(
            tunneledSocket,
            address: tryParseInternetAddress('127.0.0.1'),
            remoteAddress: (await io.InternetAddress.lookup(uri.host)).first,
            port: 1234,
            remotePort: uri.port,
            debugPrint: debugPrint,
          )),*/
          serverSide: false);
      onConnected();
    } else {
      onError('status ${response.status} ${response.reason}');
    }
    tunneledSocket = null;
  }
}
