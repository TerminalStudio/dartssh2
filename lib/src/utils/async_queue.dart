import 'dart:async';

import 'dart:collection';

/// A queue that consumers can wait asynchronously for items to be added.
class AsyncQueue<T> {
  final _data = Queue<T>();

  final _completers = Queue<Completer<T>>();

  /// The length of the queue.
  int get length => _completers.length;

  /// Return true if the queue has consumers waiting for items.
  bool get hasWaiters => _completers.isNotEmpty;

  /// Returns a [Future] that completes when an item is added to the queue.
  FutureOr<T> get next {
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
    if (_completers.isNotEmpty) {
      _completers.removeFirst().complete(value);
    } else {
      _data.add(value);
    }
  }
}
