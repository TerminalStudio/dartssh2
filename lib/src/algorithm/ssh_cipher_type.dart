import 'dart:typed_data';

import 'package:dartssh2/src/ssh_algorithm.dart';
import 'package:pointycastle/export.dart';

class SSHCipherType extends SSHAlgorithm {
  static const values = [
    aes128gcm,
    aes256gcm,
    aes128cbc,
    aes192cbc,
    aes256cbc,
    aes128ctr,
    aes192ctr,
    aes256ctr,
    chacha20poly1305,
  ];

  static const aes128ctr = SSHCipherType._(
    name: 'aes128-ctr',
    keySize: 16,
    cipherFactory: _aesCtrFactory,
  );

  static const aes192ctr = SSHCipherType._(
    name: 'aes192-ctr',
    keySize: 24,
    cipherFactory: _aesCtrFactory,
  );

  static const aes256ctr = SSHCipherType._(
    name: 'aes256-ctr',
    keySize: 32,
    cipherFactory: _aesCtrFactory,
  );

  static const aes128gcm = SSHCipherType._(
    name: 'aes128-gcm@openssh.com',
    keySize: 16,
    isAead: true,
    ivSize: 12,
    blockSize: 16,
    aeadTagSize: 16,
    cipherFactory: _aesGcmFactory,
  );

  static const aes256gcm = SSHCipherType._(
    name: 'aes256-gcm@openssh.com',
    keySize: 32,
    isAead: true,
    ivSize: 12,
    blockSize: 16,
    aeadTagSize: 16,
    cipherFactory: _aesGcmFactory,
  );

  static const aes128cbc = SSHCipherType._(
    name: 'aes128-cbc',
    keySize: 16,
    cipherFactory: _aesCbcFactory,
  );

  static const aes192cbc = SSHCipherType._(
    name: 'aes192-cbc',
    keySize: 24,
    cipherFactory: _aesCbcFactory,
  );

  static const aes256cbc = SSHCipherType._(
    name: 'aes256-cbc',
    keySize: 32,
    cipherFactory: _aesCbcFactory,
  );

  static const chacha20poly1305 = SSHCipherType._(
    name: 'chacha20-poly1305@openssh.com',
    keySize: 32,
    isAead: true,
    ivSize: 12,
    blockSize: 16,
    aeadTagSize: 16,
    cipherFactory: _chacha20Poly1305Factory,
  );

  static SSHCipherType? fromName(String name) {
    for (final value in values) {
      if (value.name == name) {
        return value;
      }
    }
    return null;
  }

  const SSHCipherType._({
    required this.name,
    required this.keySize,
    this.cipherFactory,
    this.isAead = false,
    this.aeadTagSize = 0,
    this.ivSize = 16,
    this.blockSize = 16,
  });

  @override
  final String name;

  final int keySize;

  final bool isAead;

  final int aeadTagSize;

  final int ivSize;

  final int blockSize;

  final dynamic Function()? cipherFactory;

  BlockCipher createCipher(
    Uint8List key,
    Uint8List iv, {
    required bool forEncryption,
  }) {
    if (isAead) {
      throw UnsupportedError(
        'AEAD ciphers are packet-level and do not expose BlockCipher',
      );
    }

    final factory = cipherFactory;
    if (factory == null) {
      throw StateError('No block cipher factory configured for $name');
    }

    if (key.length != keySize) {
      throw ArgumentError.value(key, 'key', 'Key must be $keySize bytes long');
    }

    if (iv.length != ivSize) {
      throw ArgumentError.value(iv, 'iv', 'IV must be $ivSize bytes long');
    }

    final cipher = factory();
    cipher.init(forEncryption, ParametersWithIV(KeyParameter(key), iv));
    return cipher;
  }

  dynamic createAEADCipher(
    Uint8List key,
    Uint8List nonce, {
    required bool forEncryption,
    Uint8List? aad,
  }) {
    if (!isAead) {
      throw StateError('Use createCipher for non-AEAD modes');
    }

    if (key.length != keySize) {
      throw ArgumentError.value(key, 'key', 'Key must be $keySize bytes long');
    }

    if (nonce.length != ivSize) {
      throw ArgumentError.value(
        nonce,
        'nonce',
        'Nonce must be $ivSize bytes long',
      );
    }

    final factory = cipherFactory;
    if (factory == null) {
      throw StateError('No AEAD cipher factory configured for $name');
    }

    final cipher = factory();
    final params = AEADParameters(
      KeyParameter(key),
      aeadTagSize * 8,
      nonce,
      aad ?? Uint8List(0),
    );
    cipher.init(forEncryption, params);
    return cipher;
  }
}

BlockCipher _aesCtrFactory() {
  final aes = AESEngine();
  return CTRBlockCipher(aes.blockSize, CTRStreamCipher(aes));
}

BlockCipher _aesCbcFactory() {
  return CBCBlockCipher(AESEngine());
}

dynamic _aesGcmFactory() {
  return GCMBlockCipher(AESEngine());
}

dynamic _chacha20Poly1305Factory() {
  return ChaCha20Poly1305(ChaCha7539Engine(), Poly1305());
}
