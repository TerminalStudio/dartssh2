import 'dart:typed_data';

import 'package:dartssh2/src/ssh_algorithm.dart';
import 'package:pointycastle/export.dart';

class SSHCipherType extends SSHAlgorithm {
  static const values = [
    aes128cbc,
    aes192cbc,
    aes256cbc,
    aes128ctr,
    aes192ctr,
    aes256ctr,
    aes128gcm,
    aes256gcm,
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

  static const aes128gcm = SSHCipherType._(
    name: 'aes128-gcm@openssh.com',
    keySize: 16,
    ivSize: 12,
    cipherFactory: _aesGcmFactory,
  );

  static const aes256gcm = SSHCipherType._(
    name: 'aes256-gcm@openssh.com',
    keySize: 32,
    ivSize: 12,
    cipherFactory: _aesGcmFactory,
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
    this.ivSize = 16,
    required this.cipherFactory,
  });

  /// The name of the algorithm. For example, `"aes256-ctr`"`.
  @override
  final String name;

  final int keySize;

  final int ivSize;

  final int blockSize = 16;

  final BlockCipher Function() cipherFactory;

  BlockCipher createCipher(
    Uint8List key,
    Uint8List iv, {
    required bool forEncryption,
  }) {
    if (key.length != keySize) {
      throw ArgumentError.value(key, 'key', 'Key must be $keySize bytes long');
    }

    if (iv.length != ivSize) {
      throw ArgumentError.value(iv, 'iv', 'IV must be $ivSize bytes long');
    }

    final cipher = cipherFactory();
    cipher.init(forEncryption, ParametersWithIV(KeyParameter(key), iv));
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

BlockCipher _aesGcmFactory() {
  // GCM is an AEAD cipher, but we'll handle it specially in the key decryption
  // For now, return a placeholder - we'll override createCipher for GCM
  throw UnimplementedError('GCM cipher factory should not be called directly');
}
