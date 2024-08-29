import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/ssh_algorithm.dart';
import 'package:dartssh2/src/utils/cipher_ext.dart';
import 'package:test/test.dart';

void main() {
  testCipher(SSHCipherType.aes128cbc);
  testCipher(SSHCipherType.aes192cbc);
  testCipher(SSHCipherType.aes256cbc);
  testCipher(SSHCipherType.aes128ctr);
  testCipher(SSHCipherType.aes192ctr);
  testCipher(SSHCipherType.aes256ctr);
  group('SSHAlgorithm', () {
    test('toString() returns correct format', () {
      final algorithm = SSHKexType.x25519;
      expect(algorithm.toString(), equals(SSHKexType.x25519.toString()));
    });
  });

  group('SSHAlgorithmList extension', () {
    test('toNameList() returns list of names', () {
      final algorithms = [SSHKexType.x25519, SSHKexType.nistp521];
      final names = algorithms.toNameList();
      expect(names, equals([SSHKexType.x25519.name, SSHKexType.nistp521.name]));
    });

    test('getByName() returns correct algorithm', () {
      final algorithms = [SSHKexType.x25519, SSHKexType.nistp521];
      final algorithm = algorithms.getByName(SSHKexType.nistp521.name);
      expect(algorithm, isNotNull);
      expect(algorithm!.name, equals(SSHKexType.nistp521.name));
    });

    test('getByName() returns null when not found', () {
      final algorithms = [SSHKexType.x25519, SSHKexType.nistp521];
      final algorithm = algorithms.getByName('nonexistent');
      expect(algorithm, isNull);
    });
  });

  test('Default values are set correctly', () {
    final algorithms = SSHAlgorithms();

    expect(
        algorithms.kex,
        equals([
          SSHKexType.x25519,
          SSHKexType.nistp521,
          SSHKexType.nistp384,
          SSHKexType.nistp256,
          SSHKexType.dhGexSha256,
          SSHKexType.dh14Sha256,
          SSHKexType.dh14Sha1,
          SSHKexType.dhGexSha1,
          SSHKexType.dh1Sha1,
        ]));

    expect(
        algorithms.hostkey,
        equals([
          SSHHostkeyType.ed25519,
          SSHHostkeyType.rsaSha512,
          SSHHostkeyType.rsaSha256,
          SSHHostkeyType.rsaSha1,
          SSHHostkeyType.ecdsa521,
          SSHHostkeyType.ecdsa384,
          SSHHostkeyType.ecdsa256,
        ]));

    expect(
        algorithms.cipher,
        equals([
          SSHCipherType.aes128ctr,
          SSHCipherType.aes128cbc,
          SSHCipherType.aes256ctr,
          SSHCipherType.aes256cbc,
        ]));

    expect(
        algorithms.mac,
        equals([
          SSHMacType.hmacSha1,
          SSHMacType.hmacSha256,
          SSHMacType.hmacSha512,
          SSHMacType.hmacMd5,
        ]));
  });
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
