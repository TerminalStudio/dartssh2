import 'package:dartssh2/src/forward/ssh_forward.dart';

/// Callback invoked to dial an SSH forwarded channel to a target [host] and [port].
typedef SSHDynamicDial = Future<SSHForwardChannel> Function(
  String host,
  int port,
);

/// Stub implementation for platforms without `dart:io`.
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
