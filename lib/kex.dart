// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:math';
import 'dart:typed_data';

import "package:pointycastle/api.dart";
import 'package:pointycastle/digests/sha1.dart';
import "package:pointycastle/digests/sha256.dart";
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/src/utils.dart';
import 'package:tweetnacl/tweetnacl.dart';

import 'package:dartssh/protocol.dart';
import 'package:dartssh/ssh.dart';

/// Mixin providing a suite of key exchange methods.
mixin SSHDiffieHellman {
  DiffieHellman dh = DiffieHellman();
  EllipticCurveDiffieHellman ecdh = EllipticCurveDiffieHellman();
  X25519DiffieHellman x25519dh = X25519DiffieHellman();
  Digest kexHash;
  BigInt K;

  void initializeDiffieHellman(int kexMethod, Random random) {
    if (KEX.x25519DiffieHellman(kexMethod)) {
      kexHash = SHA256Digest();
      x25519dh.generatePair(random);
    } else if (KEX.ellipticCurveDiffieHellman(kexMethod)) {
      kexHash = KEX.ellipticCurveHash(kexMethod);
      ecdh = EllipticCurveDiffieHellman(
          KEX.ellipticCurve(kexMethod), KEX.ellipticCurveSecretBits(kexMethod));
      ecdh.generatePair(random);
    } else if (KEX.diffieHellmanGroupExchange(kexMethod)) {
      if (kexMethod == KEX.DHGEX_SHA1) {
        kexHash = SHA1Digest();
      } else if (kexMethod == KEX.DHGEX_SHA256) {
        kexHash = SHA256Digest();
      }
    } else if (KEX.diffieHellman(kexMethod)) {
      if (kexMethod == KEX.DH14_SHA1) {
        dh = DiffieHellman.group14();
      } else if (kexMethod == KEX.DH1_SHA1) {
        dh = DiffieHellman.group1();
      }
      kexHash = SHA1Digest();
      dh.generatePair(random);
    } else {
      throw FormatException('unknown kex method: $kexMethod');
    }
  }

  void initializeDiffieHellmanGroup(BigInt p, BigInt g, Random random) {
    dh = DiffieHellman(p, g, 256);
    dh.generatePair(random);
  }
}

/// https://tools.ietf.org/html/rfc7748#section-6
class X25519DiffieHellman {
  Uint8List myPrivKey, myPubKey, remotePubKey;

  void generatePair(Random random) {
    myPrivKey = randBytes(random, 32);
    myPubKey = ScalarMult.scalseMult_base(myPrivKey);
  }

  BigInt computeSecret(Uint8List remotePubKey) {
    this.remotePubKey = remotePubKey;
    return decodeBigInt(ScalarMult.scalseMult(myPrivKey, remotePubKey));
  }
}

/// The Elliptic Curve Diffie-Hellman (ECDH) key exchange method
/// generates a shared secret from an ephemeral local elliptic curve
/// private key and ephemeral remote elliptic curve public key.
class EllipticCurveDiffieHellman {
  ECDomainParameters curve;
  int secretBits;
  BigInt x;
  Uint8List cText, sText;
  EllipticCurveDiffieHellman([this.curve, this.secretBits]);

  /// Generate ephemeral key pair.
  void generatePair(Random random) {
    do {
      x = decodeBigInt(randBits(random, secretBits)) % curve.n;
    } while (x == BigInt.zero);
    ECPoint c = curve.G * x;
    cText = c.getEncoded(false);
  }

  /// Compute shared secret.
  BigInt computeSecret(Uint8List sText) {
    this.sText = sText;
    ECPoint s = curve.curve.decodePoint(sText);
    return (s * x).x.toBigInteger();
  }
}

/// The Diffie-Hellman (DH) key exchange provides a shared secret that
/// cannot be determined by either party alone.
/// https://tools.ietf.org/html/rfc4253#section-8
class DiffieHellman {
  int gexMin = 1024, gexMax = 8192, gexPref = 2048, secretBits;
  BigInt g, p, x, e, f;
  DiffieHellman([this.p, this.g, this.secretBits]);

  /// https://tools.ietf.org/html/rfc2409 Second Oakley Group
  DiffieHellman.group1()
      : secretBits = 160,
        g = BigInt.from(2),
        p = decodeBigInt(Uint8List.fromList([
          0xff,
          0xff,
          0xff,
          0xff,
          0xff,
          0xff,
          0xff,
          0xff,
          0xc9,
          0x0f,
          0xda,
          0xa2,
          0x21,
          0x68,
          0xc2,
          0x34,
          0xc4,
          0xc6,
          0x62,
          0x8b,
          0x80,
          0xdc,
          0x1c,
          0xd1,
          0x29,
          0x02,
          0x4e,
          0x08,
          0x8a,
          0x67,
          0xcc,
          0x74,
          0x02,
          0x0b,
          0xbe,
          0xa6,
          0x3b,
          0x13,
          0x9b,
          0x22,
          0x51,
          0x4a,
          0x08,
          0x79,
          0x8e,
          0x34,
          0x04,
          0xdd,
          0xef,
          0x95,
          0x19,
          0xb3,
          0xcd,
          0x3a,
          0x43,
          0x1b,
          0x30,
          0x2b,
          0x0a,
          0x6d,
          0xf2,
          0x5f,
          0x14,
          0x37,
          0x4f,
          0xe1,
          0x35,
          0x6d,
          0x6d,
          0x51,
          0xc2,
          0x45,
          0xe4,
          0x85,
          0xb5,
          0x76,
          0x62,
          0x5e,
          0x7e,
          0xc6,
          0xf4,
          0x4c,
          0x42,
          0xe9,
          0xa6,
          0x37,
          0xed,
          0x6b,
          0x0b,
          0xff,
          0x5c,
          0xb6,
          0xf4,
          0x06,
          0xb7,
          0xed,
          0xee,
          0x38,
          0x6b,
          0xfb,
          0x5a,
          0x89,
          0x9f,
          0xa5,
          0xae,
          0x9f,
          0x24,
          0x11,
          0x7c,
          0x4b,
          0x1f,
          0xe6,
          0x49,
          0x28,
          0x66,
          0x51,
          0xec,
          0xe6,
          0x53,
          0x81,
          0xff,
          0xff,
          0xff,
          0xff,
          0xff,
          0xff,
          0xff,
          0xff
        ]));

  /// https://tools.ietf.org/html/rfc3526 Oakley Group 14
  DiffieHellman.group14()
      : secretBits = 224,
        g = BigInt.from(2),
        p = decodeBigInt(Uint8List.fromList([
          0xff,
          0xff,
          0xff,
          0xff,
          0xff,
          0xff,
          0xff,
          0xff,
          0xc9,
          0x0f,
          0xda,
          0xa2,
          0x21,
          0x68,
          0xc2,
          0x34,
          0xc4,
          0xc6,
          0x62,
          0x8b,
          0x80,
          0xdc,
          0x1c,
          0xd1,
          0x29,
          0x02,
          0x4e,
          0x08,
          0x8a,
          0x67,
          0xcc,
          0x74,
          0x02,
          0x0b,
          0xbe,
          0xa6,
          0x3b,
          0x13,
          0x9b,
          0x22,
          0x51,
          0x4a,
          0x08,
          0x79,
          0x8e,
          0x34,
          0x04,
          0xdd,
          0xef,
          0x95,
          0x19,
          0xb3,
          0xcd,
          0x3a,
          0x43,
          0x1b,
          0x30,
          0x2b,
          0x0a,
          0x6d,
          0xf2,
          0x5f,
          0x14,
          0x37,
          0x4f,
          0xe1,
          0x35,
          0x6d,
          0x6d,
          0x51,
          0xc2,
          0x45,
          0xe4,
          0x85,
          0xb5,
          0x76,
          0x62,
          0x5e,
          0x7e,
          0xc6,
          0xf4,
          0x4c,
          0x42,
          0xe9,
          0xa6,
          0x37,
          0xed,
          0x6b,
          0x0b,
          0xff,
          0x5c,
          0xb6,
          0xf4,
          0x06,
          0xb7,
          0xed,
          0xee,
          0x38,
          0x6b,
          0xfb,
          0x5a,
          0x89,
          0x9f,
          0xa5,
          0xae,
          0x9f,
          0x24,
          0x11,
          0x7c,
          0x4b,
          0x1f,
          0xe6,
          0x49,
          0x28,
          0x66,
          0x51,
          0xec,
          0xe4,
          0x5b,
          0x3d,
          0xc2,
          0x00,
          0x7c,
          0xb8,
          0xa1,
          0x63,
          0xbf,
          0x05,
          0x98,
          0xda,
          0x48,
          0x36,
          0x1c,
          0x55,
          0xd3,
          0x9a,
          0x69,
          0x16,
          0x3f,
          0xa8,
          0xfd,
          0x24,
          0xcf,
          0x5f,
          0x83,
          0x65,
          0x5d,
          0x23,
          0xdc,
          0xa3,
          0xad,
          0x96,
          0x1c,
          0x62,
          0xf3,
          0x56,
          0x20,
          0x85,
          0x52,
          0xbb,
          0x9e,
          0xd5,
          0x29,
          0x07,
          0x70,
          0x96,
          0x96,
          0x6d,
          0x67,
          0x0c,
          0x35,
          0x4e,
          0x4a,
          0xbc,
          0x98,
          0x04,
          0xf1,
          0x74,
          0x6c,
          0x08,
          0xca,
          0x18,
          0x21,
          0x7c,
          0x32,
          0x90,
          0x5e,
          0x46,
          0x2e,
          0x36,
          0xce,
          0x3b,
          0xe3,
          0x9e,
          0x77,
          0x2c,
          0x18,
          0x0e,
          0x86,
          0x03,
          0x9b,
          0x27,
          0x83,
          0xa2,
          0xec,
          0x07,
          0xa2,
          0x8f,
          0xb5,
          0xc5,
          0x5d,
          0xf0,
          0x6f,
          0x4c,
          0x52,
          0xc9,
          0xde,
          0x2b,
          0xcb,
          0xf6,
          0x95,
          0x58,
          0x17,
          0x18,
          0x39,
          0x95,
          0x49,
          0x7c,
          0xea,
          0x95,
          0x6a,
          0xe5,
          0x15,
          0xd2,
          0x26,
          0x18,
          0x98,
          0xfa,
          0x05,
          0x10,
          0x15,
          0x72,
          0x8e,
          0x5a,
          0x8a,
          0xac,
          0xaa,
          0x68,
          0xff,
          0xff,
          0xff,
          0xff,
          0xff,
          0xff,
          0xff,
          0xff
        ]));

  void generatePair(Random random) {
    if (secretBits % 8 != 0) throw FormatException();
    x = decodeBigInt(randBytes(random, secretBits ~/ 8));
    e = g.modPow(x, p);
  }

  BigInt computeSecret(BigInt f) => (this.f = f).modPow(x, p);
}
