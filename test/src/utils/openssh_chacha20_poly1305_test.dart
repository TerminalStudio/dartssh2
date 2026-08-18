import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dartssh2/src/utils/openssh_chacha20_poly1305.dart';
import 'package:pointycastle/export.dart';
import 'package:test/test.dart';

void main() {
  group('OpenSSHChaCha20Poly1305', () {
    final key = Uint8List.fromList(List<int>.generate(64, (i) => i));
    // Fixed packet vector derived from OpenSSH 10.5's cipher-chachapoly.c:
    // K_2 is bytes 0..31, K_1 is bytes 32..63, and seqnr is 0x01020304.
    final plaintext = _bytes(
      '00000010'
      '04'
      '68656c6c6f20776f726c64'
      '00010203',
    );
    final ciphertext = _bytes(
      'bc79806b'
      '92aa79deb77e06debb1f4898a8415877'
      '75aca6b6c01a2037e45c6712ba973d9b',
    );
    const sequenceNumber = 0x01020304;

    test('matches the OpenSSH packet construction', () {
      final cipher = OpenSSHChaCha20Poly1305(key);

      expect(
        cipher.encryptPacket(plaintext, sequenceNumber),
        ciphertext,
      );
      expect(
        cipher.decryptPacketLength(ciphertext, sequenceNumber),
        16,
      );
      expect(
        cipher.decryptPacket(ciphertext, sequenceNumber),
        plaintext,
      );
    });

    test('copies key material on construction', () {
      final mutableKey = Uint8List.fromList(key);
      final cipher = OpenSSHChaCha20Poly1305(mutableKey);
      mutableKey.fillRange(0, mutableKey.length, 0xff);

      expect(
        cipher.encryptPacket(plaintext, sequenceNumber),
        ciphertext,
      );
    });

    test('rejects changes to encrypted length, body, or tag', () {
      final cipher = OpenSSHChaCha20Poly1305(key);

      for (final index in [0, 4, ciphertext.length - 1]) {
        final tampered = Uint8List.fromList(ciphertext);
        tampered[index] ^= 1;

        expect(
          () => cipher.decryptPacket(tampered, sequenceNumber),
          throwsA(isA<InvalidCipherTextException>()),
        );
      }
    });

    test('uses the packet sequence number as part of the nonce', () {
      final cipher = OpenSSHChaCha20Poly1305(key);

      final first = cipher.encryptPacket(plaintext, 0);
      final second = cipher.encryptPacket(plaintext, 1);

      expect(second, isNot(first));
      expect(cipher.decryptPacket(first, 0), plaintext);
      expect(cipher.decryptPacket(second, 1), plaintext);
    });

    test('validates key, packet, and sequence number lengths', () {
      expect(
        () => OpenSSHChaCha20Poly1305(Uint8List(63)),
        throwsArgumentError,
      );

      final cipher = OpenSSHChaCha20Poly1305(key);
      expect(
        () => cipher.encryptPacket(Uint8List(3), 0),
        throwsArgumentError,
      );
      expect(
        () => cipher.decryptPacketLength(Uint8List(3), 0),
        throwsArgumentError,
      );
      expect(
        () => cipher.decryptPacket(Uint8List(19), 0),
        throwsArgumentError,
      );
      expect(
        () => cipher.encryptPacket(plaintext, -1),
        throwsRangeError,
      );
      expect(
        () => cipher.encryptPacket(plaintext, 0x100000000),
        throwsRangeError,
      );
    });
  });
}

Uint8List _bytes(String value) => Uint8List.fromList(hex.decode(value));
