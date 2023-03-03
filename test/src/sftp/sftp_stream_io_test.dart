import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:test/test.dart';

void main() {
  late SSHClient client;

  setUp(() async {
    client = await getHoneypotClient();
  });

  tearDown(() async {
    client.close();
    await client.done;
  });

  group('SftpFileWriter', () {
    test('can pause & resume', () async {
      final sftp = await client.sftp();

      final dataController = StreamController<Uint8List>(
        onListen: () => print('onListen'),
        onPause: () => print('onPause'),
        onResume: () => print('onResume'),
        onCancel: () => print('onCancel'),
      );
      final dataToUpload = dataController.stream;

      final file = await sftp.open(
        'a.out',
        mode: SftpFileOpenMode.create | SftpFileOpenMode.write,
      );
      final writer = file.write(dataToUpload);

      dataController.add(Uint8List(100));

      await Future.delayed(Duration(milliseconds: 1));
      expect(dataController.isPaused, isFalse);

      dataController.add(Uint8List(100));
      writer.pause();

      await Future.delayed(Duration(milliseconds: 1));
      expect(dataController.isPaused, isTrue);

      dataController.add(Uint8List(100));
      writer.resume();

      await Future.delayed(Duration(milliseconds: 1));
      expect(dataController.isPaused, isFalse);

      await dataController.close();
      await writer.done;
    });
  });
}

Future<SSHClient> getHoneypotClient() async {
  return SSHClient(
    await SSHSocket.connect('honeypot.terminal.studio', 2222),
    username: 'root',
    onPasswordRequest: () => 'random',
  );
}
