// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/api.dart' hide Signature;
import 'package:pointycastle/asymmetric/api.dart' as asymmetric;
import 'package:pointycastle/block/aes_fast.dart';
import 'package:pointycastle/block/modes/cbc.dart';
import 'package:pointycastle/block/modes/ctr.dart';
import 'package:pointycastle/digests/md5.dart';
import 'package:pointycastle/digests/sha1.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha384.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/curves/secp256r1.dart';
import 'package:pointycastle/ecc/curves/secp384r1.dart';
import 'package:pointycastle/ecc/curves/secp521r1.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/signers/ecdsa_signer.dart';
import 'package:pointycastle/signers/rsa_signer.dart';
import 'package:pointycastle/src/utils.dart';
import 'package:pointycastle/stream/ctr.dart';
import 'package:tweetnacl/tweetnacl.dart';

import 'package:dartssh/protocol.dart';
import 'package:dartssh/serializable.dart';

typedef NameFunction = String Function(int);
typedef SupportedFunction = bool Function(int);

/// Each of the algorithm name-lists MUST be a comma-separated list of algorithm names.
/// Each supported (allowed) algorithm MUST be listed in order of preference, from most to least.
/// https://tools.ietf.org/html/rfc4253#section-7.1
String buildPreferenceCsv(
    NameFunction name, SupportedFunction supported, int end,
    [int startAfter = 0]) {
  String ret = '';
  for (int i = 1 + startAfter; i <= end; i++) {
    if (supported(i)) ret += (ret.isEmpty ? '' : ',') + name(i);
  }
  return ret;
}

String preferenceIntersection(String intersectCsv, String supportedCsv) {
  Set<String> supported = Set<String>.of(supportedCsv.split(','));
  for (String intersect in intersectCsv.split(',')) {
    if (supported.contains(intersect)) return intersect;
  }
  return '';
}

class Key {
  static const int ED25519 = 1,
      ECDSA_SHA2_NISTP256 = 2,
      ECDSA_SHA2_NISTP384 = 3,
      ECDSA_SHA2_NISTP521 = 4,
      RSA = 5,
      End = 5;

  static int id(String name) {
    switch (name) {
      case 'ssh-rsa':
        return RSA;
      case 'ecdsa-sha2-nistp256':
        return ECDSA_SHA2_NISTP256;
      case 'ecdsa-sha2-nistp384':
        return ECDSA_SHA2_NISTP384;
      case 'ecdsa-sha2-nistp521':
        return ECDSA_SHA2_NISTP521;
      case 'ssh-ed25519':
        return ED25519;
      default:
        return 0;
    }
  }

  static String name(int id) {
    switch (id) {
      case RSA:
        return 'ssh-rsa';
      case ECDSA_SHA2_NISTP256:
        return 'ecdsa-sha2-nistp256';
      case ECDSA_SHA2_NISTP384:
        return 'ecdsa-sha2-nistp384';
      case ECDSA_SHA2_NISTP521:
        return 'ecdsa-sha2-nistp521';
      case ED25519:
        return 'ssh-ed25519';
      default:
        return '';
    }
  }

  static bool supported(int id) => true;

  static bool ellipticCurveDSA(int id) =>
      id == ECDSA_SHA2_NISTP256 ||
      id == ECDSA_SHA2_NISTP384 ||
      id == ECDSA_SHA2_NISTP521;

  static String preferenceCsv([int startAfter = 0]) =>
      buildPreferenceCsv(name, supported, End, startAfter);

  static int preferenceIntersect(String intersectCsv, [int startAfter = 0]) =>
      id(preferenceIntersection(preferenceCsv(startAfter), intersectCsv));
}

class KEX {
  static const int ECDH_SHA2_X25519 = 1,
      ECDH_SHA2_NISTP256 = 2,
      ECDH_SHA2_NISTP384 = 3,
      ECDH_SHA2_NISTP521 = 4,
      DHGEX_SHA256 = 5,
      DHGEX_SHA1 = 6,
      DH14_SHA1 = 7,
      DH1_SHA1 = 8,
      End = 8;

  static int id(String name) {
    switch (name) {
      case 'curve25519-sha256@libssh.org':
        return ECDH_SHA2_X25519;
      case 'ecdh-sha2-nistp256':
        return ECDH_SHA2_NISTP256;
      case 'ecdh-sha2-nistp384':
        return ECDH_SHA2_NISTP384;
      case 'ecdh-sha2-nistp521':
        return ECDH_SHA2_NISTP521;
      case 'diffie-hellman-group-exchange-sha256':
        return DHGEX_SHA256;
      case 'diffie-hellman-group-exchange-sha1':
        return DHGEX_SHA1;
      case 'diffie-hellman-group14-sha1':
        return DH14_SHA1;
      case 'diffie-hellman-group1-sha1':
        return DH1_SHA1;
      default:
        return 0;
    }
  }

  static String name(int id) {
    switch (id) {
      case ECDH_SHA2_X25519:
        return 'curve25519-sha256@libssh.org';
      case ECDH_SHA2_NISTP256:
        return 'ecdh-sha2-nistp256';
      case ECDH_SHA2_NISTP384:
        return 'ecdh-sha2-nistp384';
      case ECDH_SHA2_NISTP521:
        return 'ecdh-sha2-nistp521';
      case DHGEX_SHA256:
        return 'diffie-hellman-group-exchange-sha256';
      case DHGEX_SHA1:
        return 'diffie-hellman-group-exchange-sha1';
      case DH14_SHA1:
        return 'diffie-hellman-group14-sha1';
      case DH1_SHA1:
        return 'diffie-hellman-group1-sha1';
      default:
        return '';
    }
  }

  static bool supported(int id) => true;

  static bool x25519DiffieHellman(int id) => id == ECDH_SHA2_X25519;

  static bool ellipticCurveDiffieHellman(int id) =>
      id == ECDH_SHA2_NISTP256 ||
      id == ECDH_SHA2_NISTP384 ||
      id == ECDH_SHA2_NISTP521;

  static ECDomainParameters ellipticCurve(int id) {
    switch (id) {
      case ECDH_SHA2_NISTP256:
        return ECCurve_secp256r1();
      case ECDH_SHA2_NISTP384:
        return ECCurve_secp384r1();
      case ECDH_SHA2_NISTP521:
        return ECCurve_secp521r1();
      default:
        return null;
    }
  }

  static int ellipticCurveSecretBits(int id) {
    switch (id) {
      case ECDH_SHA2_NISTP256:
        return 256;
      case ECDH_SHA2_NISTP384:
        return 384;
      case ECDH_SHA2_NISTP521:
        return 521;
      default:
        return null;
    }
  }

  static Digest ellipticCurveHash(int id) {
    switch (id) {
      case ECDH_SHA2_NISTP256:
        return SHA256Digest();
      case ECDH_SHA2_NISTP384:
        return SHA384Digest();
      case ECDH_SHA2_NISTP521:
        return SHA512Digest();
      default:
        return null;
    }
  }

  static bool diffieHellmanGroupExchange(int id) =>
      id == DHGEX_SHA256 || id == DHGEX_SHA1;

  static bool diffieHellman(int id) =>
      id == DHGEX_SHA256 ||
      id == DHGEX_SHA1 ||
      id == DH14_SHA1 ||
      id == DH1_SHA1;

  static String preferenceCsv([int startAfter = 0]) =>
      buildPreferenceCsv(name, supported, End, startAfter);

  static int preferenceIntersect(String intersectCsv, [int startAfter = 0]) =>
      id(preferenceIntersection(preferenceCsv(startAfter), intersectCsv));
}

class Cipher {
  static const int AES128_CTR = 1,
      AES128_CBC = 2,
      AES256_CTR = 3,
      AES256_CBC = 4,
      End = 4;

  static int id(String name) {
    switch (name) {
      case 'aes128-ctr':
        return AES128_CTR;
      case 'aes128-cbc':
        return AES128_CBC;
      case 'aes256-ctr':
        return AES256_CTR;
      case 'aes256-cbc':
        return AES256_CBC;
      default:
        return 0;
    }
  }

  static String name(int id) {
    switch (id) {
      case AES128_CTR:
        return 'aes128-ctr';
      case AES128_CBC:
        return 'aes128-cbc';
      case AES256_CTR:
        return 'aes256-ctr';
      case AES256_CBC:
        return 'aes256-cbc';
      default:
        return '';
    }
  }

  static bool supported(int id) => true;

  static String preferenceCsv([int startAfter = 0]) =>
      buildPreferenceCsv(name, supported, End, startAfter);

  static int preferenceIntersect(String intersectCsv, [int startAfter = 0]) =>
      id(preferenceIntersection(preferenceCsv(startAfter), intersectCsv));

  static int keySize(int id) {
    switch (id) {
      case AES128_CTR:
        return 16;
      case AES128_CBC:
        return 16;
      case AES256_CTR:
        return 32;
      case AES256_CBC:
        return 32;
      default:
        throw FormatException('$id');
    }
  }

  static int blockSize(int id) {
    switch (id) {
      case AES128_CTR:
        return 16;
      case AES128_CBC:
        return 16;
      case AES256_CTR:
        return 16;
      case AES256_CBC:
        return 16;
      default:
        throw FormatException('$id');
    }
  }

  static BlockCipher cipher(int id) {
    switch (id) {
      case AES128_CTR:
        AESFastEngine aes = AESFastEngine();
        return CTRBlockCipher(aes.blockSize, CTRStreamCipher(aes));
      case AES128_CBC:
        return CBCBlockCipher(AESFastEngine());
      case AES256_CTR:
        AESFastEngine aes = AESFastEngine();
        return CTRBlockCipher(aes.blockSize, CTRStreamCipher(aes));
      case AES256_CBC:
        return CBCBlockCipher(AESFastEngine());
      default:
        throw FormatException('$id');
    }
  }
}

class MAC {
  static const int MD5 = 1,
      SHA1 = 2,
      SHA1_96 = 3,
      MD5_96 = 4,
      SHA256 = 5,
      SHA256_96 = 6,
      SHA512 = 7,
      SHA512_96 = 8,
      End = 8;

  static int id(String name) {
    switch (name) {
      case 'hmac-md5':
        return MD5;
      case 'hmac-md5-96':
        return MD5_96;
      case 'hmac-sha1':
        return SHA1;
      case 'hmac-sha1-96':
        return SHA1_96;
      case 'hmac-sha2-256':
        return SHA256;
      case 'hmac-sha2-256-96':
        return SHA256_96;
      case 'hmac-sha2-512':
        return SHA512;
      case 'hmac-sha2-512-96':
        return SHA512_96;
      default:
        return 0;
    }
  }

  static String name(int id) {
    switch (id) {
      case MD5:
        return 'hmac-md5';
      case MD5_96:
        return 'hmac-md5-96';
      case SHA1:
        return 'hmac-sha1';
      case SHA1_96:
        return 'hmac-sha1-96';
      case SHA256:
        return 'hmac-sha2-256';
      case SHA256_96:
        return 'hmac-sha2-256-96';
      case SHA512:
        return 'hmac-sha2-512';
      case SHA512_96:
        return 'hmac-sha2-512-96';
      default:
        return '';
    }
  }

  static int hashSize(int id) {
    switch (id) {
      case MD5:
        return 16;
      case MD5_96:
        return 16;
      case SHA1:
        return 20;
      case SHA1_96:
        return 20;
      case SHA256:
        return 32;
      case SHA256_96:
        return 32;
      case SHA512:
        return 64;
      case SHA512_96:
        return 64;
      default:
        return 0;
    }
  }

  static bool supported(int id) => true;

  static String preferenceCsv([int startAfter = 0]) =>
      buildPreferenceCsv(name, supported, End, startAfter);

  static int preferenceIntersect(String intersectCsv, [int startAfter = 0]) =>
      id(preferenceIntersection(preferenceCsv(startAfter), intersectCsv));

  static int prefixBytes(int id) {
    switch (id) {
      case MD5:
        return 0;
      case MD5_96:
        return 12;
      case SHA1:
        return 0;
      case SHA1_96:
        return 12;
      case SHA256:
        return 0;
      case SHA256_96:
        return 12;
      case SHA512:
        return 0;
      case SHA512_96:
        return 12;
      default:
        throw FormatException('$id');
    }
  }

  static HMac mac(int id) {
    switch (id) {
      case MD5:
        return HMac(MD5Digest(), 64);
      case MD5_96:
        return HMac(MD5Digest(), 64);
      case SHA1:
        return HMac(SHA1Digest(), 64);
      case SHA1_96:
        return HMac(SHA1Digest(), 64);
      case SHA256:
        return HMac(SHA256Digest(), 64);
      case SHA256_96:
        return HMac(SHA256Digest(), 64);
      case SHA512:
        return HMac(SHA512Digest(), 128);
      case SHA512_96:
        return HMac(SHA512Digest(), 128);
      default:
        throw FormatException('$id');
    }
  }
}

class Compression {
  static const int OpenSSHZLib = 1, None = 2, End = 2;

  static int id(String name) {
    switch (name) {
      case 'zlib@openssh.com':
        return OpenSSHZLib;
      case 'none':
        return None;
      default:
        return 0;
    }
  }

  static String name(int id) {
    switch (id) {
      case OpenSSHZLib:
        return 'zlib@openssh.com';
      case None:
        return 'none';
      default:
        return '';
    }
  }

  static bool supported(int id) => true;

  static String preferenceCsv([int startAfter = 0]) =>
      buildPreferenceCsv(name, supported, End, startAfter);

  static int preferenceIntersect(String intersectCsv, [int startAfter = 0]) =>
      id(preferenceIntersection(preferenceCsv(startAfter), intersectCsv));
}

class RSAKey with Serializable {
  String formatId = 'ssh-rsa';
  BigInt e, n;
  RSAKey([this.e, this.n]);

  @override
  int get serializedHeaderSize => 3 * 4;

  @override
  int get serializedSize =>
      serializedHeaderSize + formatId.length + mpIntLength(e) + mpIntLength(n);

  @override
  void deserialize(SerializableInput input) {
    formatId = deserializeString(input);
    if (formatId != Key.name(Key.RSA)) throw FormatException(formatId);
    e = deserializeMpInt(input);
    n = deserializeMpInt(input);
  }

  @override
  void serialize(SerializableOutput output) {
    serializeString(output, formatId);
    serializeMpInt(output, e);
    serializeMpInt(output, n);
  }
}

class RSASignature with Serializable {
  String formatId = 'ssh-rsa';
  Uint8List sig;
  RSASignature([this.sig]);

  @override
  int get serializedHeaderSize => 4 * 2 + 7;

  @override
  int get serializedSize => serializedHeaderSize + sig.length;

  @override
  void deserialize(SerializableInput input) {
    formatId = deserializeString(input);
    sig = deserializeStringBytes(input);
    if (formatId != 'ssh-rsa') throw FormatException(formatId);
  }

  @override
  void serialize(SerializableOutput output) {
    serializeString(output, formatId);
    serializeString(output, sig);
  }
}

class ECDSAKey with Serializable {
  String formatId, curveId;
  Uint8List q;
  ECDSAKey([this.formatId, this.curveId, this.q]);

  @override
  int get serializedHeaderSize => 3 * 4;

  @override
  int get serializedSize =>
      serializedHeaderSize + formatId.length + curveId.length + q.length;

  @override
  void deserialize(SerializableInput input) {
    formatId = deserializeString(input);
    if (!formatId.startsWith('ecdsa-sha2-')) throw FormatException(formatId);
    curveId = deserializeString(input);
    q = deserializeStringBytes(input);
  }

  @override
  void serialize(SerializableOutput output) {
    serializeString(output, formatId);
    serializeString(output, curveId);
    serializeString(output, q);
  }
}

class ECDSASignature with Serializable {
  String formatId;
  BigInt r, s;
  ECDSASignature([this.formatId, this.r, this.s]);

  @override
  int get serializedHeaderSize => 4 * 4;

  @override
  int get serializedSize =>
      serializedHeaderSize + formatId.length + mpIntLength(r) + mpIntLength(s);

  @override
  void deserialize(SerializableInput input) {
    formatId = deserializeString(input);
    Uint8List blob = deserializeStringBytes(input);
    if (!formatId.startsWith('ecdsa-sha2-')) throw FormatException(formatId);
    SerializableInput blobInput = SerializableInput(blob);
    r = deserializeMpInt(blobInput);
    s = deserializeMpInt(blobInput);
    if (!blobInput.done) throw FormatException('${blobInput.offset}');
  }

  @override
  void serialize(SerializableOutput output) {
    serializeString(output, formatId);
    Uint8List blob = Uint8List(4 * 2 + mpIntLength(r) + mpIntLength(s));
    SerializableOutput blobOutput = SerializableOutput(blob);
    serializeMpInt(blobOutput, r);
    serializeMpInt(blobOutput, s);
    if (!blobOutput.done) throw FormatException('${blobOutput.offset}');
    serializeString(output, blob);
  }
}

class Ed25519Key with Serializable {
  String formatId = 'ssh-ed25519';
  Uint8List key;
  Ed25519Key([this.key]);

  @override
  int get serializedHeaderSize => 4 * 2 + 11;

  @override
  int get serializedSize => serializedHeaderSize + key.length;

  @override
  void deserialize(SerializableInput input) {
    formatId = deserializeString(input);
    key = deserializeStringBytes(input);
    if (formatId != 'ssh-ed25519') throw FormatException(formatId);
  }

  @override
  void serialize(SerializableOutput output) {
    serializeString(output, formatId);
    serializeString(output, key);
  }
}

class Ed25519Signature with Serializable {
  String formatId = 'ssh-ed25519';
  Uint8List sig;
  Ed25519Signature([this.sig]);

  @override
  int get serializedHeaderSize => 4 * 2 + 11;

  @override
  int get serializedSize => serializedHeaderSize + sig.length;

  @override
  void deserialize(SerializableInput input) {
    formatId = deserializeString(input);
    sig = deserializeStringBytes(input);
    if (formatId != 'ssh-ed25519') throw FormatException(formatId);
  }

  @override
  void serialize(SerializableOutput output) {
    serializeString(output, formatId);
    serializeString(output, sig);
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
    assert(secretBits % 8 == 0);
    x = decodeBigInt(randBytes(random, secretBits ~/ 8));
    e = g.modPow(x, p);
  }

  BigInt computeSecret(BigInt f) => (this.f = f).modPow(x, p);
}

class EllipticCurveDiffieHellman {
  ECDomainParameters curve;
  int secretBits;
  BigInt x;
  Uint8List cText, sText;
  EllipticCurveDiffieHellman([this.curve, this.secretBits]);

  void generatePair(Random random) {
    x = decodeBigInt(randBits(random, secretBits)) % curve.n;
    assert(x != BigInt.zero);
    ECPoint c = curve.G * x;
    cText = c.getEncoded(false);
  }

  BigInt computeSecret(Uint8List sText) {
    this.sText = sText;
    ECPoint s = curve.curve.decodePoint(sText);
    return (s * x).x.toBigInteger();
  }
}

class X25519DiffieHellman {
  Uint8List myPrivKey, myPubKey, remotePubKey;

  void GeneratePair(Random random) {
    myPrivKey = randBytes(random, 32);
    myPubKey = ScalarMult.scalseMult_base(myPrivKey);
  }

  BigInt computeSecret() =>
      decodeBigInt(ScalarMult.scalseMult(myPrivKey, remotePubKey));
}

class Digester {
  Digest digest;
  Digester(this.digest) {
    digest.reset();
  }

  void updateByte(int x) => digest.updateByte(x);

  void updateString(String x) => update(Uint8List.fromList(x.codeUnits));

  void update(Uint8List x) => updateOffset(x, 0, x.length);

  void updateRaw(Uint8List x) => updateRawOffset(x, 0, x.length);

  void updateOffset(Uint8List x, int offset, int length) {
    updateInt(length);
    updateRawOffset(x, offset, length);
  }

  void updateRawOffset(Uint8List x, int offset, int length) =>
      digest.update(x, offset, length);

  void updateInt(int x) {
    Uint8List buf = Uint8List(4);
    ByteData.view(buf.buffer).setUint32(0, x, Endian.big);
    digest.update(buf, 0, buf.length);
  }

  void updateBigInt(BigInt x) {
    Uint8List xBytes = encodeBigInt(x);
    bool padX = x.bitLength > 0 && x.bitLength % 8 == 0;
    updateInt(xBytes.length + (padX ? 1 : 0));
    if (padX) digest.updateByte(0);
    digest.update(xBytes, 0, xBytes.length);
  }

  Uint8List finish() {
    Uint8List ret = Uint8List(digest.digestSize);
    int finalLength = digest.doFinal(ret, 0);
    assert(finalLength == ret.length);
    return ret;
  }
}

Uint8List computeExchangeHash(
    int kexMethod,
    Digest algo,
    String verC,
    String verS,
    Uint8List kexInitC,
    Uint8List kexInitS,
    Uint8List kS,
    BigInt K,
    DiffieHellman dh,
    EllipticCurveDiffieHellman ecdh,
    X25519DiffieHellman x25519dh) {
  BinaryPacket kexCPacket = BinaryPacket(kexInitC),
      kexSPacket = BinaryPacket(kexInitS);
  int kexCPacketLen = 4 + kexCPacket.length,
      kexSPacketLen = 4 + kexSPacket.length;

  Digester H = Digester(algo);
  H.updateString(verC);
  H.updateString(verS);
  H.updateOffset(kexInitC, 5, kexCPacketLen - 5 - kexCPacket.padding);
  H.updateOffset(kexInitS, 5, kexSPacketLen - 5 - kexSPacket.padding);
  H.update(kS);

  if (KEX.diffieHellmanGroupExchange(kexMethod)) {
    H.updateInt(dh.gexMin);
    H.updateInt(dh.gexPref);
    H.updateInt(dh.gexMax);
    H.updateBigInt(dh.p);
    H.updateBigInt(dh.g);
  }
  if (KEX.x25519DiffieHellman(kexMethod)) {
    H.update(x25519dh.myPubKey);
    H.update(x25519dh.remotePubKey);
  } else if (KEX.ellipticCurveDiffieHellman(kexMethod)) {
    H.update(ecdh.cText);
    H.update(ecdh.sText);
  } else {
    H.updateBigInt(dh.e);
    H.updateBigInt(dh.f);
  }
  H.updateBigInt(K);
  return H.finish();
}

bool verifyHostKey(
    Uint8List hText, int hostkeyType, Uint8List key, Uint8List sig) {
  if (hostkeyType == Key.RSA) {
    RSAKey keyMsg = RSAKey()..deserialize(SerializableInput(key));
    RSASignature sigMsg = RSASignature()..deserialize(SerializableInput(sig));
    RSASigner rsa = RSASigner(SHA1Digest(), '06052b0e03021a');
    rsa.init(
        false,
        ParametersWithRandom(
            PublicKeyParameter<asymmetric.RSAPublicKey>(
                asymmetric.RSAPublicKey(keyMsg.n, keyMsg.e)),
            null));
    return rsa.verifySignature(hText, asymmetric.RSASignature(sigMsg.sig));
  } else if (Key.ellipticCurveDSA(hostkeyType)) {
    ECDSAKey keyMsg = ECDSAKey()..deserialize(SerializableInput(key));
    ECDSASignature sigMsg = ECDSASignature()
      ..deserialize(SerializableInput(sig));
    ECDSASigner ecdsa = ECDSASigner(KEX.ellipticCurveHash(hostkeyType));
    ECDomainParameters curve = KEX.ellipticCurve(hostkeyType);
    ecdsa.init(
        false,
        PublicKeyParameter(
            ECPublicKey(curve.curve.decodePoint(keyMsg.q), curve)));
    return ecdsa.verifySignature(hText, ECSignature(sigMsg.r, sigMsg.s));
  } else if (hostkeyType == Key.ED25519) {
    Ed25519Key keyMsg = Ed25519Key()..deserialize(SerializableInput(key));
    Ed25519Signature sigMsg = Ed25519Signature()
      ..deserialize(SerializableInput(sig));
    return Signature(keyMsg.key, null).detached_verify(hText, sigMsg.sig);
  } else {
    return false;
  }
}

Uint8List deriveKey(Digest algo, Uint8List sessionId, Uint8List hText, BigInt K,
    int id, int bytes) {
  Uint8List ret = Uint8List(0);
  while (ret.length < bytes) {
    Digester digest = Digester(algo);
    digest.updateBigInt(K);
    digest.updateRaw(hText);
    if (ret.isEmpty) {
      digest.updateByte(id);
      digest.updateRaw(sessionId);
    } else {
      digest.updateRaw(ret);
    }
    ret = Uint8List.fromList(ret + digest.finish());
  }
  return viewUint8List(ret, 0, bytes);
}

Uint8List deriveChallengeText(Uint8List sessionId, String userName,
    String serviceName, String methodName, String algoName, Uint8List secret) {
  SerializableOutput output = SerializableOutput(Uint8List(2 +
      4 * 6 +
      sessionId.length +
      userName.length +
      serviceName.length +
      methodName.length +
      algoName.length +
      secret.length));
  serializeString(output, sessionId);
  output.addUint8(MSG_USERAUTH_REQUEST.ID);
  serializeString(output, userName);
  serializeString(output, serviceName);
  serializeString(output, methodName);
  output.addUint8(1);
  serializeString(output, algoName);
  serializeString(output, secret);
  assert(output.done);
  return output.buffer;
}

Uint8List applyBlockCipher(BlockCipher cipher, Uint8List m) {
  Uint8List out = Uint8List(m.length);
  assert(m.length % cipher.blockSize == 0);
  for (int offset = 0; offset < m.length; offset += cipher.blockSize) {
    cipher.processBlock(m, offset, out, offset);
  }
  return out;
}

Uint8List computeMAC(
    HMac mac, int macLen, Uint8List m, int seq, Uint8List k, int prefix) {
  mac.init(KeyParameter(k));

  Uint8List buf = Uint8List(4);
  ByteData.view(buf.buffer).setUint32(0, seq, Endian.big);
  mac.update(buf, 0, buf.length);
  mac.update(m, 0, m.length);

  assert(macLen == mac.macSize);
  Uint8List ret = Uint8List(macLen);
  int finalLen = mac.doFinal(ret, 0);
  assert(finalLen == macLen);
  return ret;
}
