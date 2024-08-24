import 'dart:io';
import 'dart:typed_data';

import 'package:dartssh4/dartssh4.dart';

void main(List<String> args) async {
  final socket = await SSHSocket.connect('localhost', 22);

  final client = SSHClient(
    socket,
    username: 'root',
    onPasswordRequest: () {
      stdout.write('Password: ');
      stdin.echoMode = false;
      return stdin.readLineSync() ?? exit(1);
    },
  );

  final shell = await client.shell();
  stdout.addStream(shell.stdout);
  stderr.addStream(shell.stderr);
  stdin.cast<Uint8List>().listen(shell.write);

  await shell.done;

  client.close();
  await client.done;
}
