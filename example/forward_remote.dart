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

  final forward = await client.forwardRemote(port: 2222);

  if (forward == null) {
    print('Failed to forward remote port');
    exit(1);
  }

  print('Forwarding remote port 2222 to localhost:22');

  await for (final connection in forward.connections) {
    final socket = await Socket.connect('localhost', 22);
    connection.stream.cast<List<int>>().pipe(socket);
    socket.cast<List<int>>().pipe(connection.sink);
  }

  client.close();
  await client.done;
}
