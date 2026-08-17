import 'dart:async';

import 'package:dartssh2/src/utils/async_queue.dart';
import 'package:dartssh2/src/utils/pending_requests.dart';
import 'package:dartssh2/src/utils/terminal_state.dart';
import 'package:test/test.dart';

void main() {
  group('AsyncQueue terminal state', () {
    test(
      'fails current and future waiters with the first terminal error',
      () async {
        final queue = AsyncQueue<int>();
        final error = StateError('closed');
        final pending = queue.next as Future<int>;
        final pendingExpectation = expectLater(pending, throwsA(same(error)));

        expect(queue.closeWithError(error), isTrue);
        expect(queue.closeWithError(StateError('later')), isFalse);

        await pendingExpectation;
        expect(() => queue.next, throwsA(same(error)));
      },
    );

    test('does not change a waiter that already received its value', () async {
      final queue = AsyncQueue<int>();
      final pending = queue.next as Future<int>;

      queue.add(7);
      queue.closeWithError(StateError('closed'));

      await expectLater(pending, completion(7));
    });
  });

  group('PendingRequests terminal state', () {
    test(
      'fails keyed waiters and rejects new keys after termination',
      () async {
        final requests = PendingRequests<int, String>();
        final error = StateError('closed');
        final first = requests.wait(1);
        final second = requests.wait(2);
        final expectations = [
          expectLater(first, throwsA(same(error))),
          expectLater(second, throwsA(same(error))),
        ];

        requests.closeWithError(error);

        await Future.wait(expectations);
        expect(() => requests.wait(3), throwsA(same(error)));
      },
    );

    test('does not change a request that already completed', () async {
      final requests = PendingRequests<int, String>();
      final pending = requests.wait(1);

      expect(requests.complete(1, 'ok'), isTrue);
      requests.closeWithError(StateError('closed'));

      await expectLater(pending, completion('ok'));
    });
  });

  group('TerminalState.bind', () {
    test('fails an operation when termination wins the race', () async {
      final state = TerminalState();
      final operation = Completer<void>();
      final error = StateError('closed');
      final bound = state.bind(() => operation.future);
      final expectation = expectLater(bound, throwsA(same(error)));

      state.terminate(error);

      await expectation;
    });

    test('preserves an operation that completed before termination', () async {
      final state = TerminalState();
      final bound = state.bind(() async => 7);

      await expectLater(bound, completion(7));
      state.terminate(StateError('closed'));
    });
  });
}
