import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:dart_console/dart_console.dart';
import 'package:dartssh2/dartssh2.dart';

import 'src/ssh_opts.dart';
import 'src/ssh_shared.dart';
import 'src/utils.dart';

final console = Console();

void main(List<String> arguments) async {
  final opts = DartSSH.parseArgs(arguments);
  final client = await startClientWithOpts(opts);

  if (opts.forwardLocal != null) {
    forwardLocal(client, opts.forwardLocal!);
  }

  if (opts.forwardRemote != null) {
    forwardRemote(client, opts.forwardRemote!);
  }

  if (opts.doNotExecute) {
    return;
  }

  if (opts.command == null) {
    await startShell(client);
  } else {
    await startCommand(client, opts.command!);
  }
}

Future<void> forwardLocal(SSHClient client, SSHForwardConfig config) async {
  final socket = await ServerSocket.bind(
    config.sourceHost ?? 'localhost',
    config.sourcePort,
  );

  final source = '${socket.address.address}:${socket.port}';
  final destination = '${config.destinationHost}:${config.destinationPort}';
  print('Forwarding (local)$source to (remote)$destination');

  await for (final connection in socket) {
    final forward = await client.forwardLocal(
      config.destinationHost,
      config.destinationPort,
      localHost: connection.address.address,
      localPort: connection.port,
    );
    connection.pipe(forward.sink);
    forward.stream.cast<List<int>>().pipe(connection);
    connection.done.then((_) => forward.close());
  }
}

Future<void> forwardRemote(SSHClient client, SSHForwardConfig config) async {
  final forward = await client.forwardRemote(
    host: config.sourceHost,
    port: config.sourcePort,
  );

  if (forward == null) {
    print('Failed to forward remote port ${config.sourcePort}');
    return;
  }

  final source = '${forward.host}:${forward.port}';
  final destination = '${config.destinationHost}:${config.destinationPort}';
  print('Forwarding (remote)$source to (local)$destination');

  await for (final connection in forward.connections) {
    final socket = await Socket.connect(
      config.destinationHost,
      config.destinationPort,
    );
    connection.stream.cast<List<int>>().pipe(socket);
    socket.pipe(connection.sink);
    socket.done.then((_) => connection.close());
  }
}

Future<void> startShell(SSHClient client) async {
  final session = await client.shell();
  final stdoutDone = stdout.addStream(session.stdout);
  final stderrDone = stderr.addStream(session.stderr);

  console.rawMode = true;
  stdin.cast<Uint8List>().listen(session.write);

  void sendTerminalSize() {
    session.resizeTerminal(console.windowWidth, console.windowHeight);
  }

  sendTerminalSize();
  final resizeNotifier = TerminalResizeNotifier();
  resizeNotifier.addListener(sendTerminalSize);

  await session.done;
  await stdoutDone;
  await stderrDone;

  console.rawMode = false;
  resizeNotifier.dispose();
  client.close();
  exit(session.exitCode ?? 0);
}

Future<void> startCommand(SSHClient client, List<String> command) async {
  final session = await client.execute(command.join(' '));
  final stdoutDone = stdout.addStream(session.stdout);
  final stderrDone = stderr.addStream(session.stderr);
  stdin.cast<Uint8List>().listen(session.write);

  await session.done;
  await stdoutDone;
  await stderrDone;

  client.close();
  exit(session.exitCode ?? 0);
}
