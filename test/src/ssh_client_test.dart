import 'package:dartssh3/dartssh3.dart';
import 'package:test/test.dart';

import '../test_utils.dart';

void main() {
  group('SSHClient', () {
    test('can connect to a ssh server', () async {
      var client = await getHoneypotClient();
      await client.authenticated;
      client.close();
    });

    test('throws SSHAuthFailError when password is wrong', () async {
      var client = SSHClient(
        await SSHSocket.connect('honeypot.terminal.studio', 2023),
        username: 'root',
        onPasswordRequest: () => 'bad-password',
      );
      try {
        await client.authenticated;
        fail('should have thrown');
      } catch (e) {
        expect(e, isA<SSHAuthFailError>());
      }
      client.close();
    });

    test('can connect to a ssh server with a public key', () async {
      var client = SSHClient(
        await SSHSocket.connect('honeypot.terminal.studio', 2022),
        username: 'root',
        identities: await getTestKeyPairs(),
      );
      await client.authenticated;
      client.close();
    });

    test('throws SSHAuthFailError when public key is wrong', () async {
      var client = SSHClient(
        await SSHSocket.connect('honeypot.terminal.studio', 2023),
        username: 'root',
        identities: await getTestKeyPairs(),
      );
      try {
        await client.authenticated;
        fail('should have thrown');
      } catch (e) {
        expect(e, isA<SSHAuthFailError>());
      }
      client.close();
    });

    test('throws SSHAuthFailError when all public keys are wrong', () async {
      var client = SSHClient(
        await SSHSocket.connect('honeypot.terminal.studio', 2023),
        username: 'root',
        identities: [
          ...await getTestKeyPairs(),
          ...await getTestKeyPairs(),
        ],
      );
      try {
        await client.authenticated;
        fail('should have thrown');
      } catch (e) {
        expect(e, isA<SSHAuthFailError>());
      }
      client.close();
    });

    test(
      'throws SSHAuthFailError when both password and public key are wrong',
      () async {
        var client = SSHClient(
          await SSHSocket.connect('honeypot.terminal.studio', 2023),
          username: 'root',
          onPasswordRequest: () => 'bad-password',
          identities: await getTestKeyPairs(),
        );
        try {
          await client.authenticated;
          fail('should have thrown');
        } catch (e) {
          expect(e, isA<SSHAuthFailError>());
        }
        client.close();
      },
    );

    test('throws SSHAuthFailError when identity is empty', () async {
      var client = SSHClient(
        await SSHSocket.connect('honeypot.terminal.studio', 2023),
        username: 'root',
        identities: [],
      );
      try {
        await client.authenticated;
        fail('should have thrown');
      } catch (e) {
        expect(e, isA<SSHAuthFailError>());
      }
      client.close();
    });

    test('throws SSHAuthAbortError when the handshake is aborted', () async {
      var client = SSHClient(
        await SSHSocket.connect('bing.com', 443),
        username: 'root',
        onPasswordRequest: () => 'bad-password',
      );

      try {
        await client.authenticated;
        fail('should have thrown');
      } catch (e) {
        expect(e, isA<SSHAuthAbortError>());
      }

      client.close();
    });

    test('can get remote ssh software version after handshaking', () async {
      var client = await getHoneypotClient();
      await client.authenticated;
      expect(client.remoteVersion, startsWith('SSH-2.0'));
      client.close();
    });
  });

  group('SSHClient.ping', () {
    test('works', () async {
      final client = await getTestClient();
      await client.ping();
    });
  });
}
