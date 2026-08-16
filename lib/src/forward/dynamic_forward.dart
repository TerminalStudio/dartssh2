import 'package:dartssh2/src/forward/dynamic_forward_stub.dart'
    if (dart.library.io) 'package:dartssh2/src/forward/dynamic_forward_io.dart'
    as impl;
import 'package:dartssh2/src/forward/ssh_forward.dart';

/// Callback invoked to dial an SSH forwarded channel to a target [host] and [port].
typedef SSHDynamicDial = Future<SSHForwardChannel> Function(
  String host,
  int port,
);

/// Starts a local SOCKS5 dynamic port forwarding proxy server.
///
/// Binds to [bindHost] and [bindPort] (or an ephemeral port if `null`/`0`).
/// Dispatches outgoing connections using the [dial] callback.
Future<SSHDynamicForward> startDynamicForward({
  required String bindHost,
  required int? bindPort,
  required SSHDynamicForwardOptions options,
  SSHDynamicConnectionFilter? filter,
  required SSHDynamicDial dial,
}) {
  return impl.startDynamicForward(
    bindHost: bindHost,
    bindPort: bindPort,
    options: options,
    filter: filter,
    dial: dial,
  );
}
