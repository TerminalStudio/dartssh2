import 'dart:convert';

import 'package:dartssh2/dartssh2.dart';

void main() async {
  final jumpServer = SSHClient(
    await SSHSocket.connect('<jump server>', 22),
    username: '...',
    onPasswordRequest: () => '...',
  );

  final client = SSHClient(
    await jumpServer.forwardLocal('<target server>', 22),
    username: '...',
    onPasswordRequest: () => '...',
  );

  print(utf8.decode(await client.run('hostname')));
  print(utf8.decode(await client.run('ifconfig')));

  client.close();
  jumpServer.close();
}
