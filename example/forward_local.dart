import 'dart:io';

import 'package:dartssh2/dartssh2.dart';

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

  await client.authenticated;

  final serverSocket = await ServerSocket.bind('localhost', 8080);

  print('Listening on ${serverSocket.address.address}:${serverSocket.port}');

  await for (final socket in serverSocket) {
    final forward = await client.forwardLocal('httpbin.org', 80);
    forward.stream.cast<List<int>>().pipe(socket);
    socket.cast<List<int>>().pipe(forward.sink);
  }

  client.close();
  await client.done;
}
