import 'dart:io';

import 'package:dartssh3/dartssh3.dart';

void main(List<String> args) async {
  final client = SSHClient(
    await SSHSocket.connect('localhost', 22),
    username: 'root',
    onPasswordRequest: () {
      stdout.write('Password: ');
      stdin.echoMode = false;
      return stdin.readLineSync() ?? exit(1);
    },
  );

  final sftp = await client.sftp();
  final file = await sftp.open(
    'file.txt',
    mode: SftpFileOpenMode.truncate | SftpFileOpenMode.write,
  );

  await file.write(File('local_file.txt').openRead().cast()).done;
  print('done');

  client.close();
  await client.done;
}
