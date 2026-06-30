import 'package:dartssh2/dartssh2.dart';
import 'package:test/test.dart';

import '../../test_utils.dart';

void main() {
  group('SSHChannel', () {
    late SSHClient client;
    late SSHSession session;

    setUp(() async {
      client = await getTestClient();
      await client.authenticated;
      session = await client.shell();
    });

    tearDown(() {
      client.close();
    });

    test('stdout stream handles remote channel close correctly', () async {
      final drainFuture = session.stdout.drain<void>();

      final closeMessage = createChannelCloseMessage(0);
      client.handlePacket(closeMessage);

      await drainFuture;
    }, timeout: const Timeout(Duration(seconds: 5)));
  });
}
