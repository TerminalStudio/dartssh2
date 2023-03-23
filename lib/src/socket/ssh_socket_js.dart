import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/src/socket/ssh_socket.dart';
import 'package:socket_io_client/socket_io_client.dart';

Future<SSHSocket> connectNativeSocket(
  String host,
  int port, {
  Duration? timeout,
}) async {
  // throw UnimplementedError("Native socket is not supported on web");

  final socket = io('http://$host:$port');

//When an event recieved from server, data is added to the stream
  socket.on('event', (data) => streamSocket.addResponse);
  socket.onDisconnect((_) => print('disconnect'));

  return _SSHNativeSocket._(socket);
}

class _SSHNativeSocket implements SSHSocket {
  final Socket _socket;

  _SSHNativeSocket._(this._socket);

  @override
  Stream<Uint8List> get stream => streamSocket.getStream;

  @override
  StreamSink<List<int>> get sink => streamSocket.getSink;

  @override
  Future<void> close() async {
    _socket.close();
  }

  @override
  Future<void> get done => streamSocket.done;

  @override
  void destroy() {
    _socket.destroy();
  }

  @override
  String toString() {
    final address = '${_socket.receiveBuffer}';
    return '_SSHNativeSocket($address)';
  }
}

// STEP1:  Stream setup
class StreamSocket {
  final _socketResponse = StreamController<Uint8List>();

  void Function(Uint8List) get addResponse => _socketResponse.sink.add;

  Stream<Uint8List> get getStream => _socketResponse.stream;

  StreamSink<List<int>> get getSink => _socketResponse.sink;

  Future<dynamic> get done => _socketResponse.done;

  void dispose() {
    _socketResponse.close();
  }
}

StreamSocket streamSocket = StreamSocket();
