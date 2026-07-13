import 'dart:async';

/// A wrapper around [Timer] that calls [ping] every [interval], and can be
/// started or stopped idempotently.
class SSHKeepAlive {
  Timer? _timer;

  final Duration interval;

  final Future Function() ping;

  bool _isPinging = false;

  SSHKeepAlive({
    required this.ping,
    this.interval = const Duration(seconds: 10),
  });

  void start() {
    _timer ??= Timer.periodic(interval, (timer) async {
      if (_isPinging) return;
      _isPinging = true;
      try {
        await ping();
      } catch (_) {
        // Ignore errors, the client transport will handle disconnection.
      } finally {
        _isPinging = false;
      }
    });
  }

  void stop() {
    _timer?.cancel();
    _timer = null;
  }
}
