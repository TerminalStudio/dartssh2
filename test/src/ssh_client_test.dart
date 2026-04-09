@Tags(['integration'])
library ssh_client_test;

import 'dart:convert';

import 'package:dartssh2/dartssh2.dart';
import 'package:test/test.dart';

import '../test_utils.dart';

void main() {
  group('SSHClient', () {
    test('can connect to a ssh server', () async {
      var client = await getHoneypotClient();
      await client.authenticated;
      client.close();
    });

    // test('throws SSHAuthFailError when password is wrong', () async {
    //   var client = SSHClient(
    //     await SSHSocket.connect('test.rebex.net', 22),
    //     username: 'root',
    //     onPasswordRequest: () => 'bad-password',
    //   );
    //   try {
    //     await client.authenticated;
    //     fail('should have thrown');
    //   } catch (e) {
    //     expect(e, isA<SSHAuthFailError>());
    //   }
    //   client.close();
    // });

    // test('hmacSha256_96 mac works', () async {
    //   var client = await getHoneypotClient(
    //     algorithms: SSHAlgorithms(mac: [SSHMacType.hmacSha256_96]),
    //   );
    //   await client.authenticated;
    //   client.close();
    // });

    // test('hmacSha512_96 mac works', () async {
    //   var client = await getHoneypotClient(
    //     algorithms: SSHAlgorithms(mac: [SSHMacType.hmacSha512_96]),
    //   );
    //   await client.authenticated;
    //   client.close();
    // });

    test('hmacSha256Etm mac works', () async {
      var client = await getHoneypotClient(
        algorithms: SSHAlgorithms(mac: [SSHMacType.hmacSha256Etm]),
      );
      await client.authenticated;
      client.close();
    });

    test('hmacSha512Etm mac works', () async {
      var client = await getHoneypotClient(
        algorithms: SSHAlgorithms(mac: [SSHMacType.hmacSha512Etm]),
      );
      await client.authenticated;
      client.close();
    });

    test('throws SSHAuthFailError when public key is wrong', () async {
      var client = SSHClient(
        await SSHSocket.connect('test.rebex.net', 22),
        username: 'demos',
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
        await SSHSocket.connect('test.rebex.net', 22),
        username: 'bad-user',
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
          await SSHSocket.connect('test.rebex.net', 22),
          username: 'demo',
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
        await SSHSocket.connect('test.rebex.net', 22),
        username: 'demo',
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
        expect((e as SSHAuthAbortError).reason!, isA<SSHSocketError>());
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

  group('SSHClient.forwardDynamic', () {
    test('starts and closes local dynamic forward', () async {
      final client = await getTestClient();

      final dynamicForward = await client.forwardDynamic(
        bindHost: '127.0.0.1',
        bindPort: 0,
      );

      expect(dynamicForward.port, greaterThan(0));
      expect(dynamicForward.isClosed, isFalse);

      await dynamicForward.close();
      expect(dynamicForward.isClosed, isTrue);

      client.close();
    });
  });

  group('SSHClient.runWithResult', () {
    test('returns command output and exit code', () async {
      final client = await getTestClient();

      final result = await client.runWithResult('echo dartssh2');

      expect(utf8.decode(result.stdout), contains('dartssh2'));
      expect(result.output, result.stdout);
      expect(result.stderr, isEmpty);
      if (result.exitCode != null) {
        expect(result.exitCode, 0);
      }
      expect(result.exitSignal, isNull);

      client.close();
    });

    test('returns non-zero exit code for failing command', () async {
      final client = await getTestClient();

      final result = await client.runWithResult('command-that-does-not-exist');

      expect(result.output, isNotEmpty);
      if (result.exitCode != null) {
        expect(result.exitCode, isNot(0));
      }
      expect(result.exitSignal, isNull);

      client.close();
    });
  });
}
