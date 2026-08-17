import 'dart:async';

import 'dart:collection';

import 'package:dartssh2/src/utils/terminal_state.dart';

/// A queue that consumers can wait asynchronously for items to be added.
class AsyncQueue<T> {
  AsyncQueue({TerminalState? terminalState})
      : terminalState = terminalState ?? TerminalState();

  final TerminalState terminalState;

  final _data = Queue<T>();

  final _completers = Queue<Completer<T>>();

  /// The length of the queue.
  int get length => _completers.length;

  /// Return true if the queue has consumers waiting for items.
  bool get hasWaiters => _completers.isNotEmpty;

  /// Returns a [Future] that completes when an item is added to the queue.
  FutureOr<T> get next {
    terminalState.throwIfTerminated();
    if (_data.isNotEmpty) {
      return _data.removeFirst();
    } else {
      final completer = Completer<T>();
      _completers.add(completer);
      return completer.future;
    }
  }

  /// Adds an item to the queue.
  void add(T value) {
    if (terminalState.isTerminated) return;
    if (_completers.isNotEmpty) {
      _completers.removeFirst().complete(value);
    } else {
      _data.add(value);
    }
  }

  /// Terminates this queue and fails all current and future waiters.
  bool closeWithError(Object error, [StackTrace? stackTrace]) {
    final didTerminate = terminalState.terminate(error, stackTrace);
    final terminalError = terminalState.error;
    final terminalStackTrace = terminalState.stackTrace;

    for (final completer in _completers) {
      completer.completeError(terminalError, terminalStackTrace);
    }
    _completers.clear();
    _data.clear();
    return didTerminate;
  }
}
