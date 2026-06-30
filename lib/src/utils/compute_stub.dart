Future<R> sshComputeImpl<M, R>(
  R Function(M message) callback,
  M message,
) {
  return Future<R>.sync(() => callback(message));
}
