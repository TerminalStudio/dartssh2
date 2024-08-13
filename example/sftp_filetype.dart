import 'dart:io';

import 'package:dartssh3/dartssh3.dart';

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

  final sftp = await client.sftp();
  final files = await sftp.listdir('/');

  for (var file in files) {
    print('${file.filename} (${file.attr.type?.name})');
  }

  client.close();
  await client.done;
}
