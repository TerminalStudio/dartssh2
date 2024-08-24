import 'dart:convert';
import 'dart:io';

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

  final sftp = await client.sftp();

  final file = await sftp.open(
    '/root/test.txt',
    mode: SftpFileOpenMode.create | SftpFileOpenMode.write,
  );

  await file.write(Stream.value(Utf8Encoder().convert('hello there!'))).done;
  await file.close();

  client.close();
  await client.done;
}
