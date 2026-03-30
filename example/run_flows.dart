import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';

Future<Uint8List> _collectBytes(Stream<Uint8List> stream) async {
  final builder = BytesBuilder(copy: false);
  await for (final chunk in stream) {
    builder.add(chunk);
  }
  return builder.takeBytes();
}

Future<void> main(List<String> args) async {
  final host = Platform.environment['SSH_HOST'] ?? 'localhost';
  final port = int.tryParse(Platform.environment['SSH_PORT'] ?? '') ?? 22;
  final username = Platform.environment['SSH_USERNAME'] ?? 'root';

  final runShellDemo = args.contains('--shell');

  final client = SSHClient(
    await SSHSocket.connect(host, port),
    username: username,
    onPasswordRequest: () {
      final envPassword = Platform.environment['SSH_PASSWORD'];
      if (envPassword != null) {
        return envPassword;
      }

      if (!stdin.hasTerminal || !stdout.hasTerminal) {
        throw StateError(
          'No terminal attached. Set SSH_PASSWORD environment variable.',
        );
      }

      stdout.write('Password for $username@$host:$port: ');
      try {
        stdin.echoMode = false;
        final password = stdin.readLineSync();
        if (password == null || password.isEmpty) {
          throw StateError('Empty password');
        }
        return password;
      } finally {
        stdin.echoMode = true;
        stdout.writeln();
      }
    },
  );

  try {
    // 1) Convenience run() for simple command output.
    final runOutput = await client.run('echo run-ok');
    stdout.writeln('[run] output: ${utf8.decode(runOutput).trim()}');

    // 2) runWithResult() with exit metadata.
    final runResult = await client.runWithResult(
      'sh -lc "echo runWithResult-out; echo runWithResult-err 1>&2; exit 7"',
    );
    stdout.writeln('[runWithResult] exitCode: ${runResult.exitCode}');
    stdout.writeln('[runWithResult] stdout: ${utf8.decode(runResult.stdout)}');
    stdout.writeln('[runWithResult] stderr: ${utf8.decode(runResult.stderr)}');

    // 3) execute() for lower-level session control.
    final session = await client.execute('echo execute-ok');
    final executeStdoutFuture = _collectBytes(session.stdout);
    final executeStderrFuture = _collectBytes(session.stderr);
    await session.done;
    final executeStdout = await executeStdoutFuture;
    final executeStderr = await executeStderrFuture;
    stdout.writeln('[execute] exitCode: ${session.exitCode}');
    stdout.writeln('[execute] stdout: ${utf8.decode(executeStdout).trim()}');
    if (executeStderr.isNotEmpty) {
      stdout.writeln('[execute] stderr: ${utf8.decode(executeStderr).trim()}');
    }

    // 4) Optional shell flow for interactive/pty scenarios.
    if (runShellDemo) {
      final shell = await client.shell(pty: const SSHPtyConfig());
      final shellStdoutFuture = _collectBytes(shell.stdout);
      final shellStderrFuture = _collectBytes(shell.stderr);

      shell.write(Uint8List.fromList('echo shell-ok; exit\n'.codeUnits));
      await shell.stdin.close();
      await shell.done;

      final shellStdout = await shellStdoutFuture;
      final shellStderr = await shellStderrFuture;
      stdout.writeln('[shell] exitCode: ${shell.exitCode}');
      stdout.writeln('[shell] stdout: ${utf8.decode(shellStdout).trim()}');
      if (shellStderr.isNotEmpty) {
        stdout.writeln('[shell] stderr: ${utf8.decode(shellStderr).trim()}');
      }
    } else {
      stdout.writeln('Shell flow skipped. Use --shell to run it.');
    }
  } finally {
    client.close();
    await client.done;
  }
}
