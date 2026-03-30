import 'package:dartssh2/src/socket/ssh_socket.dart';

Future<SSHSocket> connectNativeSocket(
  String host,
  int port, {
  Duration? timeout,
}) async {
  throw UnsupportedError(
    'SSHSocket.connect($host, $port) is not supported on web. '
    'Browsers cannot open raw TCP sockets. '
    'Use a custom SSHSocket transport over a browser-supported channel '
    '(for example, a WebSocket tunnel/proxy to an SSH endpoint).',
  );
}
