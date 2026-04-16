import 'compute_stub.dart' if (dart.library.isolate) 'compute_io.dart';

typedef SSHComputeCallback<M, R> = R Function(M message);

Future<R> sshCompute<M, R>(SSHComputeCallback<M, R> callback, M message) {
  return sshComputeImpl(callback, message);
}
