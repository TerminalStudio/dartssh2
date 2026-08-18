import 'dart:typed_data';

import 'package:dartssh2/src/utils/cipher_ext.dart';
import 'package:pointycastle/export.dart';

/// The packet cipher defined by `chacha20-poly1305@openssh.com`.
///
/// This is not the RFC 8439 AEAD construction. OpenSSH uses two independent
/// ChaCha20 keys, encrypts the packet length separately, and authenticates the
/// raw encrypted length and body with Poly1305.
class OpenSSHChaCha20Poly1305 {
  static const keySize = 64;
  static const ivSize = 0;
  static const blockSize = 8;
  static const tagSize = 16;
  static const encryptedLengthSize = 4;

  OpenSSHChaCha20Poly1305(Uint8List keyMaterial) {
    if (keyMaterial.length != keySize) {
      throw ArgumentError.value(
        keyMaterial.length,
        'keyMaterial.length',
        'OpenSSH ChaCha20-Poly1305 requires exactly $keySize bytes',
      );
    }

    // PROTOCOL.chacha20poly1305 names these K_2 and K_1 respectively.
    _payloadKey = Uint8List.fromList(keyMaterial.sublist(0, 32));
    _lengthKey = Uint8List.fromList(keyMaterial.sublist(32, 64));
  }

  late final Uint8List _payloadKey;
  late final Uint8List _lengthKey;

  /// Encrypts `packet_length || padding_length || payload || padding`.
  Uint8List encryptPacket(Uint8List packet, int sequenceNumber) {
    if (packet.length < encryptedLengthSize) {
      throw ArgumentError.value(
        packet,
        'packet',
        'Packet must include a four-byte length field',
      );
    }

    final nonce = _nonce(sequenceNumber);
    final encryptedLength = _cryptLength(
      Uint8List.sublistView(packet, 0, encryptedLengthSize),
      nonce,
    );

    final payloadCipher = _payloadCipher(nonce);
    final poly1305Key = _poly1305Key(payloadCipher);
    final encryptedBody = Uint8List(packet.length - encryptedLengthSize);
    payloadCipher.processBytes(
      packet,
      encryptedLengthSize,
      encryptedBody.length,
      encryptedBody,
      0,
    );

    final tag = _authenticationTag(
      encryptedLength,
      encryptedBody,
      poly1305Key,
    );

    return Uint8List(packet.length + tagSize)
      ..setRange(0, encryptedLengthSize, encryptedLength)
      ..setRange(
        encryptedLengthSize,
        packet.length,
        encryptedBody,
      )
      ..setRange(packet.length, packet.length + tagSize, tag);
  }

  /// Decrypts the encrypted four-byte packet length without authenticating it.
  ///
  /// SSH needs this value to determine how many bytes belong to the packet.
  /// Call [decryptPacket] before using any packet contents.
  int decryptPacketLength(Uint8List encryptedLength, int sequenceNumber) {
    if (encryptedLength.length < encryptedLengthSize) {
      throw ArgumentError.value(
        encryptedLength,
        'encryptedLength',
        'Encrypted packet length must contain at least four bytes',
      );
    }

    final plaintext = _cryptLength(
      Uint8List.sublistView(encryptedLength, 0, encryptedLengthSize),
      _nonce(sequenceNumber),
    );
    return ByteData.sublistView(plaintext).getUint32(0);
  }

  /// Authenticates and decrypts a complete OpenSSH ChaCha20-Poly1305 packet.
  ///
  /// The returned bytes include the decrypted four-byte packet length. No
  /// plaintext is returned unless the Poly1305 tag is valid.
  Uint8List decryptPacket(Uint8List packet, int sequenceNumber) {
    const minimumPacketSize = encryptedLengthSize + tagSize;
    if (packet.length < minimumPacketSize) {
      throw ArgumentError.value(
        packet,
        'packet',
        'Encrypted packet is too short',
      );
    }

    final ciphertextLength = packet.length - tagSize;
    final encryptedLength = Uint8List.sublistView(
      packet,
      0,
      encryptedLengthSize,
    );
    final encryptedBody = Uint8List.sublistView(
      packet,
      encryptedLengthSize,
      ciphertextLength,
    );
    final actualTag = Uint8List.sublistView(packet, ciphertextLength);

    final nonce = _nonce(sequenceNumber);
    final payloadCipher = _payloadCipher(nonce);
    final expectedTag = _authenticationTag(
      encryptedLength,
      encryptedBody,
      _poly1305Key(payloadCipher),
    );

    if (!_constantTimeEquals(expectedTag, actualTag)) {
      throw InvalidCipherTextException(
        'OpenSSH ChaCha20-Poly1305 authentication failed',
      );
    }

    final plaintextLength = _cryptLength(encryptedLength, nonce);
    final plaintextBody = Uint8List(encryptedBody.length);
    payloadCipher.processBytes(
      encryptedBody,
      0,
      encryptedBody.length,
      plaintextBody,
      0,
    );

    return Uint8List(ciphertextLength)
      ..setRange(0, encryptedLengthSize, plaintextLength)
      ..setRange(encryptedLengthSize, ciphertextLength, plaintextBody);
  }

  Uint8List _cryptLength(Uint8List input, Uint8List nonce) {
    final cipher = ChaCha20Engine()
      ..init(true, ParametersWithIV(KeyParameter(_lengthKey), nonce));
    final output = Uint8List(encryptedLengthSize);
    cipher.processBytes(input, 0, encryptedLengthSize, output, 0);
    return output;
  }

  ChaCha20Engine _payloadCipher(Uint8List nonce) {
    return ChaCha20Engine()
      ..init(true, ParametersWithIV(KeyParameter(_payloadKey), nonce));
  }

  Uint8List _poly1305Key(ChaCha20Engine cipher) {
    // OpenSSH generates 32 key bytes at counter zero, then explicitly seeks
    // to counter one for the packet body. Processing a full block here leaves
    // PointyCastle at exactly the same counter-one position.
    final firstBlock = Uint8List(64);
    cipher.processBytes(firstBlock, 0, firstBlock.length, firstBlock, 0);
    return Uint8List.sublistView(firstBlock, 0, 32);
  }

  Uint8List _authenticationTag(
    Uint8List encryptedLength,
    Uint8List encryptedBody,
    Uint8List poly1305Key,
  ) {
    final mac = Poly1305()..init(KeyParameter(poly1305Key));
    mac.updateAll(encryptedLength);
    mac.updateAll(encryptedBody);
    return mac.finish();
  }

  Uint8List _nonce(int sequenceNumber) {
    if (sequenceNumber < 0 || sequenceNumber > 0xffffffff) {
      throw RangeError.range(
        sequenceNumber,
        0,
        0xffffffff,
        'sequenceNumber',
      );
    }

    final nonce = Uint8List(8);
    ByteData.sublistView(nonce).setUint64(0, sequenceNumber);
    return nonce;
  }

  bool _constantTimeEquals(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    var difference = 0;
    for (var i = 0; i < a.length; i++) {
      difference |= a[i] ^ b[i];
    }
    return difference == 0;
  }
}
