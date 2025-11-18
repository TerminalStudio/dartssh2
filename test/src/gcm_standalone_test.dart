import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/block/aes.dart';
import 'package:pointycastle/block/modes/gcm.dart';
import 'package:test/test.dart';

/// Helper function to create Uint8List from hex string
Uint8List hexToBytes(String hex) {
  hex = hex.replaceAll(RegExp(r'[^0-9a-fA-F]'), '');
  final result = Uint8List(hex.length ~/ 2);
  for (int i = 0; i < hex.length; i += 2) {
    result[i ~/ 2] = int.parse(hex.substring(i, i + 2), radix: 16);
  }
  return result;
}

/// Standalone AES-GCM decrypt function matching our OpenSSH key decryption usage
Uint8List aesGcmDecrypt({
  required Uint8List key,
  required Uint8List iv,
  required Uint8List cipherAndTag,
  Uint8List? aad,
}) {
  final cipher = GCMBlockCipher(AESEngine());
  cipher.init(
    false, // decryption
    AEADParameters(
      KeyParameter(key),
      128, // tag length in bits (16 bytes = 128 bits)
      iv,
      aad ?? Uint8List(0),
    ),
  );
  return cipher.process(cipherAndTag);
}

void main() {
  group('AES-GCM Standalone Tests', () {
    test('Test Case 1: Empty plaintext with empty AAD', () {
      // From pointycastle test vectors
      final key = hexToBytes('00000000000000000000000000000000');
      final iv = hexToBytes('000000000000000000000000');
      final mac = hexToBytes('58e2fccefa7e3061367f1d57a4e7455a');
      final expectedPlain = Uint8List(0);

      // For empty plaintext, ciphertext is empty, so cipherAndTag = tag only
      final cipherAndTag = mac; // Just the tag

      final plain = aesGcmDecrypt(
        key: key,
        iv: iv,
        cipherAndTag: cipherAndTag,
      );

      expect(plain, equals(expectedPlain),
          reason: 'Empty plaintext should decrypt correctly');
    });

    test('Test Case 2: Single block plaintext with empty AAD', () {
      // From pointycastle test vectors
      final key = hexToBytes('00000000000000000000000000000000');
      final iv = hexToBytes('000000000000000000000000');
      final ciphertext = hexToBytes('0388dace60b6a392f328c2b971b2fe78');
      final mac = hexToBytes('ab6e47d42cec13bdf53a67b21257bddf');
      final expectedPlain = hexToBytes('00000000000000000000000000000000');

      // Combine ciphertext + tag
      final cipherAndTag = Uint8List(ciphertext.length + mac.length)
        ..setRange(0, ciphertext.length, ciphertext)
        ..setRange(ciphertext.length, ciphertext.length + mac.length, mac);

      final plain = aesGcmDecrypt(
        key: key,
        iv: iv,
        cipherAndTag: cipherAndTag,
      );

      expect(plain, equals(expectedPlain),
          reason: 'Single block plaintext should decrypt correctly');
    });

    test('Test Case 3: Multi-block plaintext with empty AAD', () {
      // From pointycastle test vectors
      final key = hexToBytes('feffe9928665731c6d6a8f9467308308');
      final iv = hexToBytes('cafebabefacedbaddecaf888');
      final ciphertext = hexToBytes(
          '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985');
      final mac = hexToBytes('4d5c2af327cd64a62cf35abd2ba6fab4');
      final expectedPlain = hexToBytes(
          'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255');

      // Combine ciphertext + tag
      final cipherAndTag = Uint8List(ciphertext.length + mac.length)
        ..setRange(0, ciphertext.length, ciphertext)
        ..setRange(ciphertext.length, ciphertext.length + mac.length, mac);

      final plain = aesGcmDecrypt(
        key: key,
        iv: iv,
        cipherAndTag: cipherAndTag,
      );

      expect(plain, equals(expectedPlain),
          reason: 'Multi-block plaintext should decrypt correctly');
    });

    test('Test Case 4: Multi-block plaintext with non-empty AAD', () {
      // From pointycastle test vectors
      final key = hexToBytes('feffe9928665731c6d6a8f9467308308');
      final iv = hexToBytes('cafebabefacedbaddecaf888');
      final aad = hexToBytes('feedfacedeadbeeffeedfacedeadbeefabaddad2');
      final ciphertext = hexToBytes(
          '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091');
      final mac = hexToBytes('5bc94fbc3221a5db94fae95ae7121a47');
      final expectedPlain = hexToBytes(
          'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39');

      // Combine ciphertext + tag
      final cipherAndTag = Uint8List(ciphertext.length + mac.length)
        ..setRange(0, ciphertext.length, ciphertext)
        ..setRange(ciphertext.length, ciphertext.length + mac.length, mac);

      final plain = aesGcmDecrypt(
        key: key,
        iv: iv,
        cipherAndTag: cipherAndTag,
        aad: aad,
      );

      expect(plain, equals(expectedPlain),
          reason: 'Multi-block plaintext with AAD should decrypt correctly');
    });
  });
}

