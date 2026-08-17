import 'dart:async';

/// Stores the first error that makes an asynchronous component unusable.
class TerminalState {
  bool get isTerminated => _error != null;

  Object get error {
    final error = _error;
    if (error == null) {
      throw StateError('The component has not terminated');
    }
    return error;
  }

  StackTrace get stackTrace {
    if (_error == null) {
      throw StateError('The component has not terminated');
    }
    return _stackTrace!;
  }

  Object? _error;
  StackTrace? _stackTrace;
  final _terminated = Completer<void>();

  /// Records [error] if this is the first terminal event.
  bool terminate(Object error, [StackTrace? stackTrace]) {
    if (isTerminated) return false;
    _error = error;
    _stackTrace = stackTrace ?? StackTrace.current;
    _terminated.complete();
    return true;
  }

  /// Throws the recorded terminal error, if any.
  void throwIfTerminated() {
    if (!isTerminated) return;
    Error.throwWithStackTrace(error, stackTrace);
  }

  /// Runs [operation] and fails it if this state terminates first.
  Future<T> bind<T>(FutureOr<T> Function() operation) {
    if (isTerminated) {
      return Future<T>.error(error, stackTrace);
    }

    final operationFuture = Future<T>.sync(operation);
    final terminationFuture = _terminated.future.then<T>((_) {
      Error.throwWithStackTrace(error, stackTrace);
    });
    return Future.any([operationFuture, terminationFuture]);
  }
}
