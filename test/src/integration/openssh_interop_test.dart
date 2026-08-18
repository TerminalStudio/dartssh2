@Tags(['integration'])
library;

import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:test/test.dart';

import '../../test_utils.dart';

/// Interop tests against a real OpenSSH server.
///
/// Unit tests can only prove that this library agrees with itself. These prove
/// that what it puts on the wire is what OpenSSH accepts, which is the only way
/// to catch a wire-format mistake: an encoding bug looks perfectly correct to a
/// round-trip test that encodes and decodes with the same code.
void main() {
  group('OpenSSH interop', () {
    test('connects and runs a command', () async {
      final client = await getLocalClient();
      final output = await client.run('echo dartssh2');
      expect(String.fromCharCodes(output).trim(), 'dartssh2');
      await client.close();
    });

    // One connection per algorithm, each forced on its own, so a failure names
    // the algorithm that OpenSSH refused rather than "the handshake broke".
    for (final cipher in const [
      SSHCipherType.chacha20poly1305,
      SSHCipherType.aes256gcm,
      SSHCipherType.aes128gcm,
      SSHCipherType.aes256ctr,
      SSHCipherType.aes128ctr,
    ]) {
      test('negotiates ${cipher.name}', () async {
        final client = await getLocalClient(
          algorithms: SSHAlgorithms(cipher: [cipher]),
        );
        final output = await client.run('echo ${cipher.name}');
        expect(String.fromCharCodes(output).trim(), cipher.name);
        await client.close();
      });
    }

    for (final kex in const [
      SSHKexType.x25519,
      SSHKexType.nistp256,
      SSHKexType.nistp384,
      SSHKexType.nistp521,
      SSHKexType.dhGexSha256,
      SSHKexType.dh14Sha256,
    ]) {
      test('negotiates ${kex.name}', () async {
        final client = await getLocalClient(
          algorithms: SSHAlgorithms(kex: [kex]),
        );
        // A server that does not offer the algorithm answers with
        // SSH_MSG_DISCONNECT, and SSHDisconnectError carries its explanation,
        // so a failure here says which side refused and why.
        expect(await client.run('echo kex'), isNotEmpty);
        await client.close();
      });
    }

    for (final mac in const [
      SSHMacType.hmacSha256Etm,
      SSHMacType.hmacSha512Etm,
      SSHMacType.hmacSha256,
      SSHMacType.hmacSha512,
    ]) {
      test('negotiates ${mac.name}', () async {
        final client = await getLocalClient(
          // Force a non-AEAD cipher, otherwise the MAC is never negotiated.
          algorithms: SSHAlgorithms(
            cipher: [SSHCipherType.aes256ctr],
            mac: [mac],
          ),
        );
        expect(await client.run('echo mac'), isNotEmpty);
        await client.close();
      });
    }

    test('transfers a file over SFTP', () async {
      final client = await getLocalClient();
      final sftp = await client.sftp();

      final file = await sftp.open(
        '/tmp/dartssh2-interop',
        mode: SftpFileOpenMode.create |
            SftpFileOpenMode.write |
            SftpFileOpenMode.truncate,
      );
      await file.writeBytes(Uint8List.fromList('interop'.codeUnits));
      await file.close();

      final read = await sftp.open('/tmp/dartssh2-interop');
      expect(String.fromCharCodes(await read.readBytes()), 'interop');
      await read.close();

      await sftp.close();
      await client.close();
    });
  }, skip: skipWithoutLocalSshd);
}
