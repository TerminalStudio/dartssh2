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
  );

  await client.authenticated;

  final dynamicForward = await client.forwardDynamic(
    bindHost: '127.0.0.1',
    bindPort: 1080,
    options: const SSHDynamicForwardOptions(
      handshakeTimeout: Duration(seconds: 10),
      connectTimeout: Duration(seconds: 15),
      maxConnections: 64,
    ),
    filter: (targetHost, targetPort) {
      // Allow only web ports in this sample.
      return targetPort == 80 || targetPort == 443;
    },
  );

  print(
    'SOCKS5 proxy ready on ${dynamicForward.host}:${dynamicForward.port}.',
  );
  print('Press Ctrl+C to stop.');

  ProcessSignal.sigint.watch().listen((_) async {
    await dynamicForward.close();
    client.close();
    await client.done;
    exit(0);
  });

  await Future<void>.delayed(const Duration(days: 365));
}
