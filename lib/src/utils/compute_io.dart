import 'dart:isolate';

Future<R> sshComputeImpl<M, R>(
  R Function(M message) callback,
  M message,
) {
  return Isolate.run(() => callback(message));
}
