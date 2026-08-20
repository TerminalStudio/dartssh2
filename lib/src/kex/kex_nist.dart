import 'dart:typed_data';

import 'package:dartssh2/src/kex/private_scalar.dart';
import 'package:dartssh2/src/ssh_kex.dart';
import 'package:pointycastle/ecc/curves/secp256r1.dart';
import 'package:pointycastle/ecc/curves/secp384r1.dart';
import 'package:pointycastle/ecc/curves/secp521r1.dart';
import 'package:pointycastle/pointycastle.dart';

/// The Elliptic Curve Diffie-Hellman (ECDH) key exchange method generates a
/// shared secret from an ephemeral local elliptic curve private key and
/// ephemeral remote elliptic curve public key.
class SSHKexNist implements SSHKexECDH {
  /// The elliptic curve domain parameters.
  final ECDomainParameters curve;

  /// The length of the shared secret in bytes.
  final int secretBits;

  /// Secret random number.
  late final BigInt privateKey;

  /// Public key.
  @override
  late final Uint8List publicKey;

  SSHKexNist({required this.curve, required this.secretBits}) {
    privateKey = generateEcPrivateScalar(curve.n);
    final c = curve.G * privateKey;
    publicKey = c!.getEncoded(false);
  }

  SSHKexNist.p256() : this(curve: ECCurve_secp256r1(), secretBits: 256);

  SSHKexNist.p384() : this(curve: ECCurve_secp384r1(), secretBits: 384);

  SSHKexNist.p521() : this(curve: ECCurve_secp521r1(), secretBits: 521);

  /// Compute shared secret.
  @override
  BigInt computeSecret(Uint8List remotePubilcKey) {
    final s = curve.curve.decodePoint(remotePubilcKey)!;
    return (s * privateKey)!.x!.toBigInteger()!;
  }
}
