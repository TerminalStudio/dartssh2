// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:math';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:pointycastle/api.dart' hide Signature;
import 'package:pointycastle/block/aes_fast.dart';
import 'package:pointycastle/block/modes/cbc.dart';
import 'package:pointycastle/block/modes/ctr.dart';
import 'package:pointycastle/digests/md5.dart';
import 'package:pointycastle/digests/sha1.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/src/utils.dart';
import 'package:pointycastle/stream/ctr.dart';
import 'package:tweetnacl/tweetnacl.dart';

import 'package:dartssh/protocol.dart';
import 'package:dartssh/serializable.dart';

typedef NameFunction = String Function(int);
typedef SupportedFunction = bool Function(int);

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
      DSS = 6,
      End = 6;

  static int id(String name) {
    switch (name) {
      case 'ssh-rsa':
        return RSA;
      case 'ssh-dss':
        return DSS;
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
      case DSS:
        return 'ssh-dss';
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
  static const int AES128_CTR = 1, AES128_CBC = 2, End = 2;

  static int id(String name) {
    switch (name) {
      case 'aes128-ctr':
        return AES128_CTR;
      case 'aes128-cbc':
        return AES128_CBC;
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

class DSSKey with Serializable {
  String formatId = 'ssh-dss';
  BigInt p, q, g, y;
  DSSKey(this.p, this.q, this.g, this.y);

  @override
  int get serializedHeaderSize => 5 * 4;

  @override
  int get serializedSize =>
      serializedHeaderSize +
      formatId.length +
      mpIntLength(p) +
      mpIntLength(q) +
      mpIntLength(g) +
      mpIntLength(y);

  @override
  void deserialize(SerializableInput input) {
    formatId = deserializeString(input);
    if (formatId != 'ssh-dss') throw FormatException(formatId);
    p = deserializeMpInt(input);
    q = deserializeMpInt(input);
    g = deserializeMpInt(input);
    y = deserializeMpInt(input);
  }

  @override
  void serialize(SerializableOutput output) {
    serializeString(output, formatId);
    serializeMpInt(output, p);
    serializeMpInt(output, q);
    serializeMpInt(output, g);
    serializeMpInt(output, y);
  }
}

class DSSSignature with Serializable {
  String formatId = 'ssh-dss';
  BigInt r, s;
  DSSSignature(this.r, this.s);

  @override
  int get serializedHeaderSize => 4 * 2 + 7 + 20 * 2;

  @override
  int get serializedSize => serializedHeaderSize;

  @override
  void deserialize(SerializableInput input) {
    formatId = deserializeString(input);
    Uint8List blob = deserializeStringBytes(input);
    if (formatId != 'ssh-dss' || blob.length != 40) {
      throw FormatException('$formatId ${blob.length}');
    }
    r = decodeBigInt(Uint8List.view(blob.buffer, 0, 20));
    s = decodeBigInt(Uint8List.view(blob.buffer, 20, 20));
  }

  @override
  void serialize(SerializableOutput output) {
    serializeString(output, formatId);
    Uint8List rBytes = encodeBigInt(r);
    Uint8List sBytes = encodeBigInt(s);
    assert(rBytes.length == 20);
    assert(sBytes.length == 20);
    serializeString(output, Uint8List.fromList(rBytes + sBytes));
  }
}

class RSAKey with Serializable {
  String formatId = 'ssh-rsa';
  BigInt e, n;
  RSAKey(this.e, this.n);

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
  RSASignature(this.sig);

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
  ECDSAKey(this.formatId, this.curveId, this.q);

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
  ECDSASignature(this.formatId, this.r, this.s);

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

class DiffieHellman {
  int gexMin = 1024, gexMax = 8192, gexPref = 2048;
  BigInt g, p, x, e, f;
  /*bool GeneratePair(int secret_bits, BigNumContext ctx);
  bool ComputeSecret(BigNum *K, BigNumContext ctx) { BigNumModExp(*K, f, x, p, ctx); return true; }
  static string GenerateModulus(int generator, int bits);
  static BigNum Group1Modulus (BigNum g, BigNum p, int *rand_num_bits);
  static BigNum Group14Modulus(BigNum g, BigNum p, int *rand_num_bits);*/
}

class EllipticCurveDiffieHellman {
  /*ECPair pair=0;
  ECGroup g=0;
  ECPoint c=0, s=0;*/
  String cText, sText;
  /*bool GeneratePair(ECDef curve, BigNumContext ctx);
  bool ComputeSecret(BigNum *K, BigNumContext ctx);*/
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
    H.updateString(ecdh.cText);
    H.updateString(ecdh.sText);
  } else {
    H.updateBigInt(dh.e);
    H.updateBigInt(dh.f);
  }
  H.updateBigInt(K);
  return H.finish();
}

bool verifyHostKey(
    Uint8List hText, int hostkeyType, Uint8List key, Uint8List sig) {
  if (hostkeyType == Key.ED25519) {
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
