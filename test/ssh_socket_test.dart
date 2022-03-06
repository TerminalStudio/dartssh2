import 'package:dartssh2/dartssh2.dart';
import 'package:test/test.dart';

void main() {
  group('SSHSocket', () {
    test('can establish tcp connections', () async {
      final socket = await SSHSocket.connect('honeypot.terminal.studio', 2022);
      final firstPacket = await socket.stream.first;
      expect(firstPacket, isNotEmpty);
      await socket.close();
    });
  });
}
