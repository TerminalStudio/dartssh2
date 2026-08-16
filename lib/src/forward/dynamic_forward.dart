import 'package:dartssh2/src/forward/dynamic_forward_stub.dart'
    if (dart.library.io) 'package:dartssh2/src/forward/dynamic_forward_io.dart'
    as impl;
import 'package:dartssh2/src/forward/ssh_forward.dart';

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
  return impl.startDynamicForward(
    bindHost: bindHost,
    bindPort: bindPort,
    options: options,
    filter: filter,
    dial: dial,
  );
}
