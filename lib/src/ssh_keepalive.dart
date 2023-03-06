import 'dart:async';

/// A wrapper around [Timer] that calls [ping] every [interval], and can be
/// started or stopped idempotently.
class SSHKeepAlive {
  Timer? _timer;

  final Duration interval;

  final Future Function() ping;

  SSHKeepAlive({
    required this.ping,
    this.interval = const Duration(seconds: 10),
  });

  void start() {
    _timer ??= Timer.periodic(interval, (timer) async {
      await ping();
    });
  }

  void stop() {
    _timer?.cancel();
    _timer = null;
  }
}
