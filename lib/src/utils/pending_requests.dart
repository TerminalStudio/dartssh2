import 'dart:async';

import 'package:dartssh2/src/utils/terminal_state.dart';

/// Futures waiting for replies identified by a request key.
class PendingRequests<K, V> {
  PendingRequests({TerminalState? terminalState})
      : terminalState = terminalState ?? TerminalState();

  final TerminalState terminalState;

  final _completers = <K, Completer<V>>{};

  /// The keys that currently have a waiter.
  Iterable<K> get keys => _completers.keys.toList(growable: false);

  /// Whether [key] currently has a waiter.
  bool isWaiting(K key) => _completers.containsKey(key);

  /// Returns the existing waiter for [key], or registers a new one.
  Future<V> wait(K key) {
    terminalState.throwIfTerminated();
    return _completers.putIfAbsent(key, Completer<V>.new).future;
  }

  /// Completes the waiter for [key]. Returns false if there is no waiter.
  bool complete(K key, V value) {
    final completer = _completers.remove(key);
    if (completer == null) return false;
    completer.complete(value);
    return true;
  }

  /// Fails the waiter for [key]. Returns false if there is no waiter.
  bool fail(K key, Object error, [StackTrace? stackTrace]) {
    final completer = _completers.remove(key);
    if (completer == null) return false;
    completer.completeError(error, stackTrace ?? StackTrace.current);
    return true;
  }

  /// Terminates this collection and fails all current and future waiters.
  bool closeWithError(Object error, [StackTrace? stackTrace]) {
    final didTerminate = terminalState.terminate(error, stackTrace);
    final terminalError = terminalState.error;
    final terminalStackTrace = terminalState.stackTrace;

    for (final completer in _completers.values) {
      completer.completeError(terminalError, terminalStackTrace);
    }
    _completers.clear();
    return didTerminate;
  }
}
