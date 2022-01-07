import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/src/socket/ssh_socket_io.dart'
    if (dart.library.js) 'package:dartssh2/next/socket/ssh_socket_js.dart';

abstract class SSHSocket {
  static Future<SSHSocket> connect(
    String host,
    int port, {
    Duration? timeout,
  }) async {
    return await connectNativeSocket(host, port, timeout: timeout);
  }

  Stream<Uint8List> get stream;

  StreamSink<List<int>> get sink;

  Future<void> close();

  void destroy();
}
