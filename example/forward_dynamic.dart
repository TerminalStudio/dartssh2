import 'dart:async';
import 'dart:io';

import 'package:dartssh2/dartssh2.dart';

Future<void> main() async {
  final host = Platform.environment['SSH_HOST'] ?? 'localhost';
  final port = int.tryParse(Platform.environment['SSH_PORT'] ?? '') ?? 22;
  final username = Platform.environment['SSH_USERNAME'] ?? 'root';
  final password = Platform.environment['SSH_PASSWORD'];

  final socket = await SSHSocket.connect(host, port);

  final client = SSHClient(
    socket,
    username: username,
    onPasswordRequest: () => password,
    onVerifyHostKey: (host, verifier) {
      // WARNING: Accepting any host key for demonstration purposes only.
      // In production, verify the host key against a known trusted value.
      print('WARNING: Host key verification disabled for testing.');
      return true;
    },
  );

  final dynamicForward = await client.forwardDynamic(
    bindHost: '127.0.0.1',
    bindPort: 1080,
  );

  print(
    'SOCKS5 proxy ready on ${dynamicForward.host}:${dynamicForward.port}.',
  );
  print('Press Ctrl+C to stop.');

  StreamSubscription<void>? sigintSub;
  StreamSubscription<void>? sigtermSub;

  Future<void> shutdown() async {
    await sigintSub?.cancel();
    await sigtermSub?.cancel();
    await dynamicForward.close();
    client.close();
    await client.done;
    exit(0);
  }

  sigintSub = ProcessSignal.sigint.watch().listen((_) => shutdown());
  sigtermSub = ProcessSignal.sigterm.watch().listen((_) => shutdown());

  await client.done;
}
