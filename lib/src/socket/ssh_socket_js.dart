import 'package:dartssh2/src/socket/ssh_socket.dart';

Future<SSHSocket> connectNativeSocket(
  String host,
  int port, {
  Duration? timeout,
}) async {
  throw UnimplementedError(
    'Native socket is not supported on web. '
    'To use dartssh2 in browser, you have to bring your own implementation '
    'of SSHSocket.',
  );
}
