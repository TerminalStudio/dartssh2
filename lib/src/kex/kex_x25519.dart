import 'dart:typed_data';

import 'package:dartssh2/src/ssh_kex.dart';
import 'package:dartssh2/src/utils/bigint.dart';
import 'package:dartssh2/src/utils/list.dart';
import 'package:pinenacl/tweetnacl.dart';

class SSHKexX25519 implements SSHKexECDH {
  /// Randomly generated private key.
  late final Uint8List privateKey;

  /// Public key computed from the private key.
  @override
  late final Uint8List publicKey;

  SSHKexX25519() {
    privateKey = randomBytes(32);
    publicKey = _ScalarMult.scalseMultBase(privateKey);
  }

  @override
  BigInt computeSecret(Uint8List remotePublicKey) {
    final secret = _ScalarMult.scalseMult(privateKey, remotePublicKey);
    return decodeBigIntWithSign(1, secret);
  }
}

/// Scalar multiplication, Implements curve25519.
class _ScalarMult {
  /// Length of scalar in bytes.
  static final int _scalarLength = 32;

  /// Length of group element in bytes.
  static final int groupElementLength = 32;

  /// Multiplies an integer n by a group element p and returns the resulting
  /// group element.
  static Uint8List scalseMult(Uint8List n, Uint8List p) {
    if (n.length != _scalarLength) {
      throw ArgumentError('n must be 32 bytes long');
    }

    if (p.length != groupElementLength) {
      throw ArgumentError('p must be 32 bytes long');
    }

    final q = Uint8List(_scalarLength);

    TweetNaCl.crypto_scalarmult(q, n, p);

    return q;
  }

  /// Multiplies an integer n by a standard group element and returns the
  /// resulting group element.
  static Uint8List scalseMultBase(Uint8List n) {
    if (n.length != _scalarLength) {
      throw ArgumentError('n must be 32 bytes long');
    }

    final q = Uint8List(_scalarLength);

    TweetNaCl.crypto_scalarmult_base(q, n);

    return q;
  }
}
