import 'dart:async';

import 'package:dartssh2/src/ssh_keepalive.dart';
import 'package:test/test.dart';

void main() {
  group('SSHKeepAlive', () {
    test('calls ping at specified interval', () async {
      var pingCount = 0;
      final completer = Completer<void>();

      final keepAlive = SSHKeepAlive(
        interval: const Duration(milliseconds: 10),
        ping: () async {
          pingCount++;
          if (pingCount >= 3) {
            completer.complete();
          }
        },
      );

      keepAlive.start();
      await completer.future;
      keepAlive.stop();

      expect(pingCount, greaterThanOrEqualTo(3));
    });

    test('prevents overlapping pings', () async {
      var pingCount = 0;
      var activePings = 0;
      var maxActivePings = 0;
      final completer = Completer<void>();

      final keepAlive = SSHKeepAlive(
        interval: const Duration(milliseconds: 10),
        ping: () async {
          pingCount++;
          activePings++;
          if (activePings > maxActivePings) {
            maxActivePings = activePings;
          }
          // Sleep longer than the interval to cause an overlapping tick
          await Future.delayed(const Duration(milliseconds: 50));
          activePings--;
          if (pingCount >= 2 && !completer.isCompleted) {
            completer.complete();
          }
        },
      );

      keepAlive.start();
      // Wait for a few intervals. If overlapping wasn't prevented, activePings would exceed 1.
      await Future.delayed(const Duration(milliseconds: 100));
      keepAlive.stop();

      expect(maxActivePings, equals(1));
    });

    test('handles ping errors and resets isPinging status', () async {
      var pingCount = 0;
      final completer = Completer<void>();

      final keepAlive = SSHKeepAlive(
        interval: const Duration(milliseconds: 10),
        ping: () async {
          pingCount++;
          if (pingCount == 1) {
            throw Exception('ping failed');
          }
          if (pingCount == 2) {
            completer.complete();
          }
        },
      );

      keepAlive.start();
      await completer.future;
      keepAlive.stop();

      expect(pingCount, equals(2));
    });
  });
}
