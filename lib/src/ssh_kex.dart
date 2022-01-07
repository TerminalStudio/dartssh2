import 'dart:typed_data';

/// Interface for a class that implements key exchange logic.
abstract class SSHKex {}

/// Interface for a class that implements ECDH key exchange.
abstract class SSHKexECDH implements SSHKex {
  /// Public key computed from the private key.
  Uint8List get publicKey;

  BigInt computeSecret(Uint8List remotePublicKey);
}
