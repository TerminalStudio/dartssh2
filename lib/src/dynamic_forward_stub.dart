import 'package:dartssh2/src/ssh_forward.dart';

typedef SSHDynamicDial = Future<SSHForwardChannel> Function(
  String host,
  int port,
);

Future<SSHDynamicForward> startDynamicForward({
  required String bindHost,
  required int? bindPort,
  required SSHDynamicForwardOptions options,
  SSHDynamicConnectionFilter? filter,
  required SSHDynamicDial dial,
}) {
  throw UnsupportedError(
    'Dynamic forwarding requires dart:io and is not supported on this platform.',
  );
}
