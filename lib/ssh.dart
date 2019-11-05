// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:typed_data';

import 'package:pointycastle/api.dart' hide Signature;
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
import 'package:pointycastle/src/utils.dart';
import 'package:pointycastle/stream/ctr.dart';

import 'package:dartssh/identity.dart';
import 'package:dartssh/kex.dart';
import 'package:dartssh/protocol.dart';
import 'package:dartssh/serializable.dart';

typedef NameFunction = String Function(int);
typedef SupportedFunction = bool Function(int);

/// Valid URLs include 127.0.0.1, 127.0.0.1:22, wss://webssh.
Uri parseUri(String uriText) {
  Uri uri;
  try {
    uri = Uri.parse(uriText);
  } catch (_) {
    uri = Uri.parse('ssh://$uriText');
  }
  if (!uri.hasScheme) uri = uri = Uri.parse('ssh://$uriText');
  if (uri.scheme == 'ssh' && !uri.hasPort) uri = Uri.parse('$uri:22');
  return uri;
}

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

/// Choose the first algorithm that satisfies the conditions.
String preferenceIntersection(String intersectCsv, String supportedCsv,
    [bool server = false]) {
  if (server) {
    String swapCsv = intersectCsv;
    intersectCsv = supportedCsv;
    supportedCsv = swapCsv;
  }
  Set<String> supported = Set<String>.of(supportedCsv.split(','));
  for (String intersect in intersectCsv.split(',')) {
    if (supported.contains(intersect)) return intersect;
  }
  return '';
}

/// Limits cipher suite support to the specified parameter, if not null.
void applyCipherSuiteOverrides(
    String kex, String key, String cipher, String mac) {
  if (kex != null) {
    final int kexOverride = KEX.id(kex);
    if (kexOverride == 0) {
      throw FormatException(
          'unknown kex: $kex, supported: ${KEX.preferenceCsv()}');
    }
    KEX.supported = (int id) => id == kexOverride;
  }
  if (key != null) {
    final int keyOverride = Key.id(key);
    if (keyOverride == 0) {
      throw FormatException(
          'unknown key: $key, supported: ${Key.preferenceCsv()}');
    }
    Key.supported = (int id) => id == keyOverride;
  }
  if (cipher != null) {
    final int cipherOverride = Cipher.id(cipher);
    if (cipherOverride == 0) {
      throw FormatException(
          'unknown cipher: $cipher, supported: ${Cipher.preferenceCsv()}');
    }
    Cipher.supported = (int id) => id == cipherOverride;
  }
  if (mac != null) {
    final int macOverride = MAC.id(mac);
    if (macOverride == 0) {
      throw FormatException(
          'unknown mac: $mac, supported: ${MAC.preferenceCsv()}');
    }
    MAC.supported = (int id) => id == macOverride;
  }
}

/// This protocol has been designed to operate with almost any public key
/// format, encoding, and algorithm (signature and/or encryption).
class Key {
  static const int ED25519 = 1,
      ECDSA_SHA2_NISTP256 = 2,
      ECDSA_SHA2_NISTP384 = 3,
      ECDSA_SHA2_NISTP521 = 4,
      RSA = 5,
      End = 5;

  static int id(String name) {
    if (name == null) return 0;
    switch (name) {
      case 'ssh-ed25519':
        return ED25519;
      case 'ecdsa-sha2-nistp256':
        return ECDSA_SHA2_NISTP256;
      case 'ecdsa-sha2-nistp384':
        return ECDSA_SHA2_NISTP384;
      case 'ecdsa-sha2-nistp521':
        return ECDSA_SHA2_NISTP521;
      case 'ssh-rsa':
        return RSA;
      default:
        return 0;
    }
  }

  static String name(int id) {
    switch (id) {
      case ED25519:
        return 'ssh-ed25519';
      case ECDSA_SHA2_NISTP256:
        return 'ecdsa-sha2-nistp256';
      case ECDSA_SHA2_NISTP384:
        return 'ecdsa-sha2-nistp384';
      case ECDSA_SHA2_NISTP521:
        return 'ecdsa-sha2-nistp521';
      case RSA:
        return 'ssh-rsa';
      default:
        return '';
    }
  }

  static SupportedFunction supported = (int id) => true;

  static bool ellipticCurveDSA(int id) =>
      id == ECDSA_SHA2_NISTP256 ||
      id == ECDSA_SHA2_NISTP384 ||
      id == ECDSA_SHA2_NISTP521;

  static ECDomainParameters ellipticCurve(int id) {
    switch (id) {
      case ECDSA_SHA2_NISTP256:
        return ECCurve_secp256r1();
      case ECDSA_SHA2_NISTP384:
        return ECCurve_secp384r1();
      case ECDSA_SHA2_NISTP521:
        return ECCurve_secp521r1();
      default:
        return null;
    }
  }

  static String ellipticCurveName(int id) {
    switch (id) {
      case ECDSA_SHA2_NISTP256:
        return 'nistp256';
      case ECDSA_SHA2_NISTP384:
        return 'nistp384';
      case ECDSA_SHA2_NISTP521:
        return 'nistp521';
      default:
        return null;
    }
  }

  static int ellipticCurveSecretBits(int id) {
    switch (id) {
      case ECDSA_SHA2_NISTP256:
        return 256;
      case ECDSA_SHA2_NISTP384:
        return 384;
      case ECDSA_SHA2_NISTP521:
        return 521;
      default:
        return null;
    }
  }

  static Digest ellipticCurveHash(int id) {
    switch (id) {
      case ECDSA_SHA2_NISTP256:
        return SHA256Digest();
      case ECDSA_SHA2_NISTP384:
        return SHA384Digest();
      case ECDSA_SHA2_NISTP521:
        return SHA512Digest();
      default:
        return null;
    }
  }

  static String preferenceCsv([int startAfter = 0]) =>
      buildPreferenceCsv(name, supported, End, startAfter);

  static int preferenceIntersect(String intersectCsv,
          [bool server = false, int startAfter = 0]) =>
      id(preferenceIntersection(
          preferenceCsv(startAfter), intersectCsv, server));
}

/// The key exchange method specifies how one-time session keys are generated for
/// encryption and for authentication, and how the server authentication is done.
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
    if (name == null) return 0;
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

  static SupportedFunction supported = (int id) => true;

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

  static int preferenceIntersect(String intersectCsv,
          [bool server = false, int startAfter = 0]) =>
      id(preferenceIntersection(
          preferenceCsv(startAfter), intersectCsv, server));
}

// When encryption is in effect, the packet length, padding length, payload,
// and padding fields of each packet MUST be encrypted with the given algorithm.
class Cipher {
  static const int AES128_CTR = 1,
      AES128_CBC = 2,
      AES256_CTR = 3,
      AES256_CBC = 4,
      End = 4;

  static int id(String name) {
    if (name == null) return 0;
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

  static SupportedFunction supported = (int id) => true;

  static String preferenceCsv([int startAfter = 0]) =>
      buildPreferenceCsv(name, supported, End, startAfter);

  static int preferenceIntersect(String intersectCsv,
          [bool server = false, int startAfter = 0]) =>
      id(preferenceIntersection(
          preferenceCsv(startAfter), intersectCsv, server));

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

/// Data integrity is protected by including with each packet a MAC that is computed
/// from a shared secret, packet sequence number, and the contents of the packet.
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
    if (name == null) return 0;
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

  static SupportedFunction supported = (int id) => true;

  static String preferenceCsv([int startAfter = 0]) =>
      buildPreferenceCsv(name, supported, End, startAfter);

  static int preferenceIntersect(String intersectCsv,
          [bool server = false, int startAfter = 0]) =>
      id(preferenceIntersection(
          preferenceCsv(startAfter), intersectCsv, server));

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

/// If compression has been negotiated, the 'payload' field (and only it)
/// will be compressed using the negotiated algorithm.
class Compression {
  static const int OpenSSHZLib = 1, None = 2, End = 2;

  static int id(String name) {
    if (name == null) return 0;
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

  static SupportedFunction supported = (int id) => true;

  static String preferenceCsv([int startAfter = 0]) =>
      buildPreferenceCsv(name, supported, End, startAfter);

  static int preferenceIntersect(String intersectCsv,
          [bool server = false, int startAfter = 0]) =>
      id(preferenceIntersection(
          preferenceCsv(startAfter), intersectCsv, server));
}

/// Hashes SSH protocol data without first serializing it.
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
    if (finalLength != ret.length) throw FormatException();
    return ret;
  }
}

/// The exchange hash is used to authenticate the key exchange and SHOULD be kept secret.
Uint8List computeExchangeHash(
    bool server,
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
  if (server) H.updateString(verS);
  H.updateString(verC);
  if (!server) H.updateString(verS);
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
    if (server) H.update(x25519dh.remotePubKey);
    H.update(x25519dh.myPubKey);
    if (!server) H.update(x25519dh.remotePubKey);
  } else if (KEX.ellipticCurveDiffieHellman(kexMethod)) {
    if (server) H.update(ecdh.sText);
    H.update(ecdh.cText);
    if (!server) H.update(ecdh.sText);
  } else {
    if (server) H.updateBigInt(dh.f);
    H.updateBigInt(dh.e);
    if (!server) H.updateBigInt(dh.f);
  }
  H.updateBigInt(K);
  return H.finish();
}

/// Verifies that [key] signed [exH] producing [sig].
bool verifyHostKey(
    Uint8List exH, int hostkeyType, Uint8List key, Uint8List sig) {
  if (hostkeyType == Key.RSA) {
    return verifyRSASignature(RSAKey()..deserialize(SerializableInput(key)),
        RSASignature()..deserialize(SerializableInput(sig)), exH);
  } else if (Key.ellipticCurveDSA(hostkeyType)) {
    return verifyECDSASignature(
        hostkeyType,
        ECDSAKey()..deserialize(SerializableInput(key)),
        ECDSASignature()..deserialize(SerializableInput(sig)),
        exH);
  } else if (hostkeyType == Key.ED25519) {
    return verifyEd25519Signature(
        Ed25519Key()..deserialize(SerializableInput(key)),
        Ed25519Signature()..deserialize(SerializableInput(sig)),
        exH);
  } else {
    return false;
  }
}

/// https://tools.ietf.org/html/rfc4253#section-7.2
Uint8List deriveKey(Digest algo, Uint8List sessionId, Uint8List exH, BigInt K,
    int id, int bytes) {
  Uint8List ret = Uint8List(0);
  while (ret.length < bytes) {
    Digester digest = Digester(algo);
    digest.updateBigInt(K);
    digest.updateRaw(exH);
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

/// https://tools.ietf.org/html/rfc4252#section-7
Uint8List deriveChallenge(Uint8List sessionId, String userName,
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
  if (!output.done) {
    throw FormatException('${output.offset}/${output.buffer.length}');
  }
  return output.buffer;
}

/// Transforms [m] by [cipher] provided [m.length] is a multiple of [cipher.blockSize].
Uint8List applyBlockCipher(BlockCipher cipher, Uint8List m) {
  Uint8List out = Uint8List(m.length);
  if (m.length % cipher.blockSize != 0) {
    throw FormatException('${m.length} not multiple of ${cipher.blockSize}');
  }
  for (int offset = 0; offset < m.length; offset += cipher.blockSize) {
    cipher.processBlock(m, offset, out, offset);
  }
  return out;
}

/// Signs [seq] | [m] with [k] using [mac].
Uint8List computeMAC(
    HMac mac, int macLen, Uint8List m, int seq, Uint8List k, int prefix) {
  mac.init(KeyParameter(k));

  Uint8List buf = Uint8List(4);
  ByteData.view(buf.buffer).setUint32(0, seq, Endian.big);
  mac.update(buf, 0, buf.length);
  mac.update(m, 0, m.length);

  if (macLen != mac.macSize) throw FormatException();
  Uint8List ret = Uint8List(macLen);
  int finalLen = mac.doFinal(ret, 0);
  if (finalLen != macLen) throw FormatException();

  if (prefix != 0) {
    return viewUint8List(ret, 0, prefix);
  } else {
    return ret;
  }
}
