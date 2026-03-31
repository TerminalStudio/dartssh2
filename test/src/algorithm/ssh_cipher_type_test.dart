import 'dart:typed_data';
import 'dart:mirrors';

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
  testAEADCipher(SSHCipherType.aes128gcm);
  testAEADCipher(SSHCipherType.aes256gcm);
  testAEADCipher(SSHCipherType.chacha20poly1305);
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

  group('AEAD cipher metadata', () {
    test('AES-GCM ciphers are marked as AEAD', () {
      expect(SSHCipherType.aes128gcm.isAead, isTrue);
      expect(SSHCipherType.aes256gcm.isAead, isTrue);
      expect(SSHCipherType.aes128gcm.ivSize, 12);
      expect(SSHCipherType.aes128gcm.aeadTagSize, 16);
    });

    test('AEAD ciphers do not expose BlockCipher API', () {
      expect(
        () => SSHCipherType.aes128gcm.createCipher(
          Uint8List(SSHCipherType.aes128gcm.keySize),
          Uint8List(SSHCipherType.aes128gcm.ivSize),
          forEncryption: true,
        ),
        throwsA(isA<UnsupportedError>()),
      );
    });

    test('fromName resolves AES-GCM ciphers', () {
      expect(
        SSHCipherType.fromName('aes128-gcm@openssh.com'),
        SSHCipherType.aes128gcm,
      );
      expect(
        SSHCipherType.fromName('aes256-gcm@openssh.com'),
        SSHCipherType.aes256gcm,
      );
    });

    test('createCipher throws when cipher factory is missing', () {
      final library = reflectClass(SSHCipherType).owner as LibraryMirror;
      final ctor = MirrorSystem.getSymbol('_', library);
      final dynamic custom = reflectClass(SSHCipherType).newInstance(
        ctor,
        const [],
        {
          #name: 'custom-null-factory',
          #keySize: 16,
          #ivSize: 16,
          #blockSize: 16,
          #isAead: false,
          #aeadTagSize: 0,
          #cipherFactory: null,
        },
      ).reflectee;

      expect(
        () => custom.createCipher(
          Uint8List(16),
          Uint8List(16),
          forEncryption: true,
        ),
        throwsA(isA<StateError>()),
      );
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
          SSHKexType.dh16Sha512,
          SSHKexType.dh14Sha256,
          SSHKexType.dhGexSha256,
          SSHKexType.dh14Sha1,
          SSHKexType.dhGexSha1,
          SSHKexType.dh1Sha1,
        ]));

    expect(
        algorithms.hostkey,
        equals([
          SSHHostkeyType.ed25519,
          SSHHostkeyType.ecdsa521,
          SSHHostkeyType.ecdsa384,
          SSHHostkeyType.ecdsa256,
          SSHHostkeyType.rsaSha512,
          SSHHostkeyType.rsaSha256,
          SSHHostkeyType.rsaSha1,
        ]));

    expect(
        algorithms.cipher,
        equals([
          SSHCipherType.aes256ctr,
          SSHCipherType.aes128ctr,
          SSHCipherType.aes256gcm,
          SSHCipherType.aes128gcm,
          SSHCipherType.chacha20poly1305,
          SSHCipherType.aes256cbc,
          SSHCipherType.aes128cbc,
        ]));

    expect(
        algorithms.mac,
        equals([
          SSHMacType.hmacSha256Etm,
          SSHMacType.hmacSha512Etm,
          SSHMacType.hmacSha256,
          SSHMacType.hmacSha512,
          SSHMacType.hmacSha1,
          SSHMacType.hmacMd5,
          SSHMacType.hmacSha256_96,
          SSHMacType.hmacSha512_96,
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

  test('$type rejects invalid key length', () {
    expect(
      () => type.createCipher(
        Uint8List(type.keySize - 1),
        Uint8List(type.blockSize),
        forEncryption: true,
      ),
      throwsA(isA<ArgumentError>()),
    );
  });

  test('$type rejects invalid IV length', () {
    expect(
      () => type.createCipher(
        Uint8List(type.keySize),
        Uint8List(type.ivSize - 1),
        forEncryption: true,
      ),
      throwsA(isA<ArgumentError>()),
    );
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

void testAEADCipher(SSHCipherType type) {
  test('$type AEAD encrypt/decrypt', () {
    expect(type.isAead, isTrue, reason: 'Expected AEAD cipher');

    final key = Uint8List(type.keySize);
    final nonce = Uint8List(
        12); // AEAD (GCM/ChaCha20-Poly1305) typically uses 12-byte nonce
    final aad = Uint8List.fromList('additional data'.codeUnits);
    final plainText = Uint8List.fromList('Hello, AEAD cipher!'.codeUnits);

    // ENCRYPTION (AAD is provided via AEADParameters)
    final encrypter =
        type.createAEADCipher(key, nonce, forEncryption: true, aad: aad);

    Uint8List encryptedWithTag;
    if (type.name.contains('gcm')) {
      // GCM supports one-shot process returning ciphertext+tag
      encryptedWithTag = encrypter.process(plainText);
      expect(
          encryptedWithTag.length, equals(plainText.length + type.aeadTagSize));
    } else {
      // ChaCha20-Poly1305 requires doFinal to append tag
      final outLen = encrypter.getOutputSize(plainText.length);
      encryptedWithTag = Uint8List(outLen);
      var written = encrypter.processBytes(
          plainText, 0, plainText.length, encryptedWithTag, 0);
      written += encrypter.doFinal(encryptedWithTag, written);
      expect(written, equals(plainText.length + type.aeadTagSize));
      // Trim if underlying allocated larger buffer
      if (written != encryptedWithTag.length) {
        encryptedWithTag = Uint8List.sublistView(encryptedWithTag, 0, written);
      }
    }

    // DECRYPTION (AAD is provided via AEADParameters)
    final decrypter =
        type.createAEADCipher(key, nonce, forEncryption: false, aad: aad);

    if (type.name.contains('gcm')) {
      final decrypted = decrypter.process(encryptedWithTag);
      expect(decrypted, equals(plainText));
    } else {
      final decOutLen = decrypter.getOutputSize(encryptedWithTag.length);
      final decrypted = Uint8List(decOutLen);
      var dwritten = decrypter.processBytes(
          encryptedWithTag, 0, encryptedWithTag.length, decrypted, 0);
      dwritten += decrypter.doFinal(decrypted, dwritten);
      expect(dwritten, equals(plainText.length));
      expect(decrypted, equals(plainText));
    }
  });
}
