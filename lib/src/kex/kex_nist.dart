import 'dart:typed_data';

import 'package:dartssh2/src/ssh_kex.dart';
import 'package:dartssh2/src/utils/bigint.dart';
import 'package:dartssh2/src/utils/list.dart';
import 'package:dartssh2/src/utils/compute.dart';
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
    privateKey = _generatePrivateKey();
    final c = curve.G * privateKey;
    publicKey = c!.getEncoded(false);
  }

  SSHKexNist._({
    required this.curve,
    required this.secretBits,
    required this.privateKey,
    required this.publicKey,
  });

  SSHKexNist.p256() : this(curve: ECCurve_secp256r1(), secretBits: 256);

  SSHKexNist.p384() : this(curve: ECCurve_secp384r1(), secretBits: 384);

  SSHKexNist.p521() : this(curve: ECCurve_secp521r1(), secretBits: 521);

  static Future<SSHKexNist> p256Async() => createAsync('p256');

  static Future<SSHKexNist> p384Async() => createAsync('p384');

  static Future<SSHKexNist> p521Async() => createAsync('p521');

  static Future<SSHKexNist> createAsync(String curveName) async {
    final (privateKey, publicKey) =
        await sshCompute(_computeNistKeyPair, curveName);
    final curve = _getCurveByName(curveName);
    final secretBits = _getSecretBitsByName(curveName);
    return SSHKexNist._(
      curve: curve,
      secretBits: secretBits,
      privateKey: privateKey,
      publicKey: publicKey,
    );
  }

  /// Compute shared secret.
  @override
  BigInt computeSecret(Uint8List remotePubilcKey) {
    final s = curve.curve.decodePoint(remotePubilcKey)!;
    return (s * privateKey)!.x!.toBigInteger()!;
  }

  Future<BigInt> computeSecretAsync(Uint8List remotePublicKey) async {
    final curveName = _getNameByCurve(curve);
    return sshCompute(
      _computeNistSecret,
      (curveName, privateKey, remotePublicKey),
    );
  }

  BigInt _generatePrivateKey() {
    late BigInt x;
    do {
      x = decodeBigIntWithSign(1, randomBytes(secretBits ~/ 8)) % curve.n;
    } while (x == BigInt.zero);
    return x;
  }
}

ECDomainParameters _getCurveByName(String name) {
  switch (name) {
    case 'p256':
      return ECCurve_secp256r1();
    case 'p384':
      return ECCurve_secp384r1();
    case 'p521':
      return ECCurve_secp521r1();
    default:
      throw ArgumentError('Unknown curve name: $name');
  }
}

int _getSecretBitsByName(String name) {
  switch (name) {
    case 'p256':
      return 256;
    case 'p384':
      return 384;
    case 'p521':
      return 521;
    default:
      throw ArgumentError('Unknown curve name: $name');
  }
}

String _getNameByCurve(ECDomainParameters curve) {
  if (curve is ECCurve_secp256r1) return 'p256';
  if (curve is ECCurve_secp384r1) return 'p384';
  if (curve is ECCurve_secp521r1) return 'p521';
  throw ArgumentError('Unknown curve type: $curve');
}

(BigInt, Uint8List) _computeNistKeyPair(String curveName) {
  final curve = _getCurveByName(curveName);
  final secretBits = _getSecretBitsByName(curveName);

  late BigInt x;
  do {
    x = decodeBigIntWithSign(1, randomBytes(secretBits ~/ 8)) % curve.n;
  } while (x == BigInt.zero);

  final c = curve.G * x;
  final publicKey = c!.getEncoded(false);

  return (x, publicKey);
}

BigInt _computeNistSecret((String, BigInt, Uint8List) args) {
  final curveName = args.$1;
  final privateKey = args.$2;
  final remotePublicKey = args.$3;

  final curve = _getCurveByName(curveName);
  final s = curve.curve.decodePoint(remotePublicKey)!;
  return (s * privateKey)!.x!.toBigInteger()!;
}
