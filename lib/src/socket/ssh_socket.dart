import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh3/src/socket/ssh_socket_io.dart'
    if (dart.library.js) 'package:dartssh3/src/socket/ssh_socket_js.dart';

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

  /// A future that will complete when the consumer closes, or when an error occurs.
  Future<void> get done;

  /// Closes the socket, returning the same future as [done].
  Future<void> close();

  void destroy();
}
