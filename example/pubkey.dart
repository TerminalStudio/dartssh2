import 'dart:convert';
import 'dart:io';

import 'package:dartssh3/dartssh3.dart';

void main(List<String> args) async {
  final socket = await SSHSocket.connect('localhost', 22);

  final client = SSHClient(
    socket,
    username: 'root',
    identities: [
      // A single private key file may contain multiple keys.
      ...SSHKeyPair.fromPem(await File('path/to/id_rsa').readAsString()),
    ],
  );

  final uptime = await client.run('uptime');
  print(utf8.decode(uptime));

  client.close();
  await client.done;
}
