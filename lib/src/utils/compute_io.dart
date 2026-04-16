import 'dart:async';
import 'dart:isolate';

class _ComputeConfiguration<M, R> {
  final R Function(M message) callback;
  final M message;
  final SendPort resultPort;

  const _ComputeConfiguration({
    required this.callback,
    required this.message,
    required this.resultPort,
  });
}

class _ComputeError {
  final String error;
  final String stackTrace;

  const _ComputeError(this.error, this.stackTrace);
}

void _spawn<M, R>(_ComputeConfiguration<M, R> configuration) {
  try {
    final result = configuration.callback(configuration.message);
    Isolate.exit(configuration.resultPort, result);
  } catch (error, stackTrace) {
    Isolate.exit(
      configuration.resultPort,
      _ComputeError(error.toString(), stackTrace.toString()),
    );
  }
}

Future<R> sshComputeImpl<M, R>(
  R Function(M message) callback,
  M message,
) async {
  final resultPort = RawReceivePort();
  final completer = Completer<R>();

  resultPort.handler = (response) {
    resultPort.close();
    if (response is _ComputeError) {
      completer.completeError(
        RemoteError(response.error, response.stackTrace),
      );
      return;
    }
    completer.complete(response as R);
  };

  await Isolate.spawn<_ComputeConfiguration<M, R>>(
    _spawn,
    _ComputeConfiguration<M, R>(
      callback: callback,
      message: message,
      resultPort: resultPort.sendPort,
    ),
  );

  return completer.future;
}
