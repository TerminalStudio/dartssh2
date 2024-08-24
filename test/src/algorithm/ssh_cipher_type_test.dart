import 'dart:typed_data';

import 'package:dartssh4/src/algorithm/ssh_cipher_type.dart';
import 'package:dartssh4/src/utils/cipher_ext.dart';
import 'package:test/test.dart';

void main() {
  testCipher(SSHCipherType.aes128cbc);
  testCipher(SSHCipherType.aes192cbc);
  testCipher(SSHCipherType.aes256cbc);
  testCipher(SSHCipherType.aes128ctr);
  testCipher(SSHCipherType.aes192ctr);
  testCipher(SSHCipherType.aes256ctr);
}

void testCipher(SSHCipherType type) {
  test('$type encrypt/decrypt', () {
    final key = Uint8List(type.keySize);
    final iv = Uint8List(type.blockSize);
    final encrypter = type.createCipher(key, iv, forEncryption: true);
    final decrypter = type.createCipher(key, iv, forEncryption: false);

    final plainText = Uint8List(type.blockSize * 100);
    for (var i = 0; i < plainText.length; i++) {
      plainText[i] = i & 0xff;
    }

    final cipherText = encrypter.processAll(plainText);
    final decrypted = decrypter.processAll(cipherText);

    expect(decrypted, plainText);
  });

  // test('$type needs init after reset', () {
  //   final key = Uint8List(type.keySize);
  //   final iv = Uint8List(type.blockSize);
  //   final encrypter = type.createCipher(key, iv, forEncryption: true);
  //   encrypter.processAll(Uint8List(type.blockSize));
  //   encrypter.reset();
  //   expect(
  //     () => encrypter.processAll(Uint8List(type.blockSize)),
  //     throwsA(isA<StateError>()),
  //   );
  // });
}
