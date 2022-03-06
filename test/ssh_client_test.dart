import 'dart:io';

import 'package:dartssh2/dartssh2.dart';
import 'package:test/test.dart';

/// honeypot.terminal.studio:2022 honeypot that accepts all passwords and public-keys
/// honeypot.terminal.studio:2023 honeypot that denies all passwords and public-keys
void main() {
  group('SSHSocket', () {
    test('can connect to a ssh server', () async {
      var client = await getTestClient();
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

    test('throws SSHAuthFailError when both password and public key are wrong',
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
    });

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
      var client = await getTestClient();
      await client.authenticated;
      expect(client.remoteVersion, startsWith('SSH-2.0'));
      client.close();
    });
  });
}

Future<SSHClient> getTestClient() async {
  return SSHClient(
    await SSHSocket.connect('honeypot.terminal.studio', 2022),
    username: 'root',
    onPasswordRequest: () => 'random',
  );
}

Future<List<SSHKeyPair>> getTestKeyPairs() async {
  final ed25519Private = 'test/ssh-ed25519/id_ed25519';
  final pem = await File(ed25519Private).readAsString();
  return SSHKeyPair.fromPem(pem);
}
