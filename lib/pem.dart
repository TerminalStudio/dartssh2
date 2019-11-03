// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:pointycastle/api.dart' hide Signature;
import 'package:pointycastle/asymmetric/api.dart' as asymmetric;
import 'package:pointycastle/ecc/api.dart';
import 'package:tweetnacl/tweetnacl.dart' as tweetnacl;

import 'package:dartssh/identity.dart';
import 'package:dartssh/protocol.dart';
import 'package:dartssh/serializable.dart';
import 'package:dartssh/ssh.dart';
import 'package:dartssh/transport.dart';

/// Privacy-Enhanced Mail (PEM) is a de facto file format for storing and sending
/// cryptographic keys, certificates, and other data.
Identity parsePem(String text,
    {StringFunction getPassword, Identity identity}) {
  identity ??= Identity();
  const String beginText = '-----BEGIN ',
      endText = '-----END ',
      termText = '-----';
  int beginBegin, beginEnd, endBegin, endEnd;
  if ((beginBegin = text.indexOf(beginText)) == -1) {
    throw FormatException('missing $beginText');
  }
  if ((beginEnd = text.indexOf(termText, beginBegin + beginText.length)) ==
      -1) {
    throw FormatException('missing $termText');
  }
  if ((endBegin = text.indexOf(endText, beginEnd + termText.length)) == -1) {
    throw FormatException('missing $endText');
  }
  if ((endEnd = text.indexOf(termText, endBegin + endText.length)) == -1) {
    throw FormatException('missing $termText');
  }

  String type = text.substring(beginBegin + beginText.length, beginEnd);
  if (type != text.substring(endBegin + endText.length, endEnd)) {
    throw FormatException('type disagreement: $type');
  }

  int start = beginEnd + termText.length, end = endBegin;
  if (start < text.length && text[start] == '\r') start++;
  if (start < text.length && text[start] == '\n') start++;

  String headersEndText = '\n\n', procType;
  int headersStart = -1, headersEnd = text.indexOf(headersEndText, start);
  if (headersEnd == -1 || headersEnd >= end) {
    headersEndText = '\r\n\r\n';
    headersEnd = text.indexOf(headersEndText, start);
  }
  if (headersEnd != -1 && headersEnd < end) {
    headersStart = start;
    start = headersEnd + headersEndText.length;
    for (String header
        in LineSplitter().convert(text.substring(headersStart, headersEnd))) {
      if (header.startsWith('Proc-Type: ')) {
        procType = header.substring(11);
      } else if (header.startsWith('DEK-Info: ')) {
        throw FormatException('not supported');
      }
    }
  }

  String base64text = '';
  for (String line in LineSplitter().convert(text.substring(start, end))) {
    base64text += line.trim();
  }
  Uint8List payload = base64.decode(base64text);

  switch (type) {
    case 'OPENSSH PRIVATE KEY':
      OpenSSHKey openssh = OpenSSHKey()
        ..deserialize(SerializableInput(payload));
      Uint8List privateKey;
      switch (openssh.kdfname) {
        case 'bcrypt':
          OpenSSHBCryptKDFOptions kdfoptions = OpenSSHBCryptKDFOptions()
            ..deserialize(SerializableInput(openssh.kdfoptions));
          int cipherAlgo;
          if (openssh.ciphername == 'aes256-cbc') {
            cipherAlgo = Cipher.AES256_CBC;
          } else {
            throw FormatException('cipher ${openssh.ciphername}');
          }
          privateKey = opensshKeyCrypt(
              false,
              (getPassword != null ? getPassword() : '').codeUnits,
              kdfoptions.salt,
              kdfoptions.rounds,
              openssh.privatekey,
              cipherAlgo);
          break;

        case 'none':
          privateKey = openssh.privatekey;
          break;

        default:
          throw FormatException('kdf ${openssh.kdfname}');
      }
      SerializableInput input = SerializableInput(privateKey);
      OpenSSHPrivateKeyHeader().deserialize(input);
      String type = deserializeString(SerializableInput(input.viewRemaining()));
      switch (type) {
        case 'ssh-ed25519':
          OpenSSHEd25519PrivateKey ed25519 = OpenSSHEd25519PrivateKey()
            ..deserialize(input);
          if (identity.ed25519 != null) throw FormatException();
          identity.ed25519 =
              tweetnacl.Signature.keyPair_fromSecretKey(ed25519.privkey);
          if (!equalUint8List(identity.ed25519.publicKey, ed25519.pubkey)) {
            throw FormatException();
          }
          return identity;

        case 'ssh-rsa':
          OpenSSHRSAPrivateKey rsaPrivateKey = OpenSSHRSAPrivateKey()
            ..deserialize(input);
          if (identity.rsaPublic != null || identity.rsaPrivate != null) {
            throw FormatException();
          }
          return identity
            ..rsaPublic =
                asymmetric.RSAPublicKey(rsaPrivateKey.n, rsaPrivateKey.e)
            ..rsaPrivate = asymmetric.RSAPrivateKey(rsaPrivateKey.n,
                rsaPrivateKey.d, rsaPrivateKey.p, rsaPrivateKey.q);

        default:
          if (type.startsWith('ecdsa-')) {
            OpenSSHECDSAPrivateKey ecdsaPrivateKey = OpenSSHECDSAPrivateKey()
              ..deserialize(input);
            ECDomainParameters curve =
                Key.ellipticCurve(ecdsaPrivateKey.keyTypeId);
            if (identity.ecdsaPublic != null || identity.ecdsaPrivate != null) {
              throw FormatException();
            }
            identity
              ..ecdsaKeyType = ecdsaPrivateKey.keyTypeId
              ..ecdsaPublic =
                  ECPublicKey(curve.curve.decodePoint(ecdsaPrivateKey.q), curve)
              ..ecdsaPrivate = ECPrivateKey(ecdsaPrivateKey.d, curve);

            if (curve.G * identity.ecdsaPrivate.d != identity.ecdsaPublic.Q) {
              throw FormatException();
            }
            return identity;
          } else {
            throw FormatException('type $type');
          }
      }
      break;

    case 'RSA PRIVATE KEY':
      RSAPrivateKey rsaPrivateKey = RSAPrivateKey()
        ..deserialize(SerializableInput(payload));
      if (identity.rsaPublic != null || identity.rsaPrivate != null) {
        throw FormatException();
      }
      return identity
        ..rsaPublic = asymmetric.RSAPublicKey(rsaPrivateKey.n, rsaPrivateKey.e)
        ..rsaPrivate = asymmetric.RSAPrivateKey(
            rsaPrivateKey.n, rsaPrivateKey.d, rsaPrivateKey.p, rsaPrivateKey.q);

    default:
      throw FormatException('type not supported: $type');
  }
}

/// https://tools.ietf.org/html/rfc3447#appendix-A.1.2
class RSAPrivateKey extends Serializable {
  BigInt version, n, e, d, p, q, exponent1, exponent2, coefficient;

  @override
  int get serializedSize => null;

  /// https://gist.github.com/proteye/982d9991922276ccfb011dfc55443d74
  @override
  void deserialize(SerializableInput input) {
    ASN1Parser asn1Parser = ASN1Parser(input.viewRemaining());
    ASN1Sequence pkSeq = asn1Parser.nextObject();
    version = (pkSeq.elements[0] as ASN1Integer).valueAsBigInteger;
    n = (pkSeq.elements[1] as ASN1Integer).valueAsBigInteger;
    e = (pkSeq.elements[2] as ASN1Integer).valueAsBigInteger;
    d = (pkSeq.elements[3] as ASN1Integer).valueAsBigInteger;
    p = (pkSeq.elements[4] as ASN1Integer).valueAsBigInteger;
    q = (pkSeq.elements[5] as ASN1Integer).valueAsBigInteger;
    exponent1 = (pkSeq.elements[6] as ASN1Integer).valueAsBigInteger;
    exponent2 = (pkSeq.elements[7] as ASN1Integer).valueAsBigInteger;
    coefficient = (pkSeq.elements[8] as ASN1Integer).valueAsBigInteger;
  }

  @override
  void serialize(SerializableOutput output) {}

  String toString() => 'version: $version, n: $n, d: $d, e: $e, p: $p, q: $q';
}

/// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
class OpenSSHKey extends Serializable {
  String magic = 'openssh-key-v1', ciphername, kdfname;
  Uint8List kdfoptions, privatekey;
  List<Uint8List> publickeys;
  OpenSSHKey([this.ciphername, this.kdfname, this.kdfoptions, this.privatekey]);

  @override
  int get serializedHeaderSize => 5 * 4 + 15;

  @override
  int get serializedSize =>
      serializedHeaderSize +
      ciphername.length +
      kdfname.length +
      kdfoptions.length +
      privatekey.length +
      publickeys.fold(0, (v, e) => v += e.length);

  @override
  void deserialize(SerializableInput input) {
    Uint8List nullTerminatedMagic = input.getBytes(15);
    magic = String.fromCharCodes(nullTerminatedMagic, 0, 14);
    if (magic != 'openssh-key-v1') throw FormatException('wrong magic: $magic');

    ciphername = deserializeString(input);
    kdfname = deserializeString(input);
    kdfoptions = deserializeStringBytes(input);
    publickeys = List<Uint8List>(input.getUint32());
    for (int i = 0; i < publickeys.length; i++) {
      publickeys[i] = deserializeStringBytes(input);
    }
    privatekey = deserializeStringBytes(input);
  }

  @override
  void serialize(SerializableOutput output) {
    output.addBytes(magic.codeUnits);
    output.addUint8(0);

    serializeString(output, ciphername);
    serializeString(output, kdfname);
    serializeString(output, kdfoptions);
    output.addUint32(publickeys.length);
    for (Uint8List publickey in publickeys) {
      serializeString(output, publickey);
    }
    serializeString(output, privatekey);
  }
}

/// Before the key is encrypted, a random integer is assigned to both checkint fields so successful
/// decryption can be quickly checked by verifying that both checkint fields hold the same value.
class OpenSSHPrivateKeyHeader extends Serializable {
  int checkint1 = 0, checkint2 = 0;
  OpenSSHPrivateKeyHeader();

  @override
  int get serializedHeaderSize => 2 * 4;

  @override
  int get serializedSize => serializedHeaderSize;

  @override
  void deserialize(SerializableInput input) {
    checkint1 = input.getUint32();
    checkint2 = input.getUint32();
    if (checkint1 != checkint2) {
      throw FormatException('$checkint1 != $checkint2');
    }
  }

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(checkint1);
    output.addUint32(checkint2);
  }
}

/// https://github.com/openssh/openssh-portable/blob/master/sshkey.c#L3274
class OpenSSHRSAPrivateKey extends Serializable {
  String keytype = 'ssh-rsa', comment;
  BigInt n, e, d, iqmp, p, q;
  OpenSSHRSAPrivateKey();

  @override
  int get serializedHeaderSize => 7 * 4;

  @override
  int get serializedSize =>
      serializedHeaderSize +
      mpIntLength(n) +
      mpIntLength(e) +
      mpIntLength(d) +
      mpIntLength(iqmp) +
      mpIntLength(p) +
      mpIntLength(q) +
      comment.length;

  @override
  void deserialize(SerializableInput input) {
    keytype = deserializeString(input);
    if (keytype != 'ssh-rsa') throw FormatException('$keytype');
    n = deserializeMpInt(input);
    e = deserializeMpInt(input);
    d = deserializeMpInt(input);
    iqmp = deserializeMpInt(input);
    p = deserializeMpInt(input);
    q = deserializeMpInt(input);
    comment = deserializeString(input);
  }

  @override
  void serialize(SerializableOutput output) {}

  String toString() => 'n: $n, d: $d, e: $e, p: $p, q: $q';
}

/// https://github.com/openssh/openssh-portable/blob/master/sshkey.c#L3223
class OpenSSHECDSAPrivateKey extends Serializable {
  String keytype, curveName, comment;
  int keyTypeId;
  Uint8List q;
  BigInt d;
  OpenSSHECDSAPrivateKey();

  @override
  int get serializedHeaderSize => 4 * 5;

  @override
  int get serializedSize =>
      serializedHeaderSize +
      keytype.length +
      curveName.length +
      q.length +
      mpIntLength(d);

  @override
  void deserialize(SerializableInput input) {
    keytype = deserializeString(input);
    if (!keytype.startsWith('ecdsa-sha2-')) throw FormatException('$keytype');
    keyTypeId = Key.id(keytype);
    if (!Key.ellipticCurveDSA(keyTypeId)) throw FormatException();
    curveName = deserializeString(input);
    q = deserializeStringBytes(input);
    d = deserializeMpInt(input);
    comment = deserializeString(input);
  }

  @override
  void serialize(SerializableOutput output) {}
}

/// https://github.com/openssh/openssh-portable/blob/master/sshkey.c#L2446
class OpenSSHEd25519PrivateKey extends Serializable {
  String keytype = 'ssh-ed25519', comment;
  Uint8List pubkey, privkey;
  OpenSSHEd25519PrivateKey([this.pubkey, this.privkey, this.comment]);

  @override
  int get serializedHeaderSize => 4 * 4;

  @override
  int get serializedSize =>
      serializedHeaderSize +
      keytype.length +
      pubkey.length +
      privkey.length +
      comment.length;

  @override
  void deserialize(SerializableInput input) {
    keytype = deserializeString(input);
    if (keytype != 'ssh-ed25519') throw FormatException('$keytype');
    pubkey = deserializeStringBytes(input);
    if (pubkey.length != 32) throw FormatException('${pubkey.length}');
    privkey = deserializeStringBytes(input);
    if (privkey.length != 64) throw FormatException('${privkey.length}');
    comment = deserializeString(input);
  }

  @override
  void serialize(SerializableOutput output) {
    serializeString(output, keytype);
    serializeString(output, pubkey);
    serializeString(output, privkey);
    serializeString(output, comment);
  }
}

/// The options: string salt, uint32 rounds are concatenated and represented as a string.
class OpenSSHBCryptKDFOptions extends Serializable {
  Uint8List salt;
  int rounds;
  OpenSSHBCryptKDFOptions([this.salt, this.rounds]);

  @override
  int get serializedHeaderSize => 2 * 4;

  @override
  int get serializedSize => serializedHeaderSize + salt.length;

  @override
  void deserialize(SerializableInput input) {
    salt = deserializeStringBytes(input);
    rounds = input.getUint32();
  }

  @override
  void serialize(SerializableOutput output) {
    serializeString(output, salt);
    output.addUint32(rounds);
  }
}

Uint8List opensshKeyCrypt(bool forEncryption, Uint8List password,
    Uint8List salt, int rounds, Uint8List input, int cipherAlgo) {
  int keySize = Cipher.keySize(cipherAlgo),
      blockSize = Cipher.blockSize(cipherAlgo);
  Uint8List key = bcryptPbkdf(password, salt, keySize + blockSize, rounds);
  BlockCipher cipher = Cipher.cipher(cipherAlgo);
  cipher.init(
      forEncryption,
      ParametersWithIV(KeyParameter(viewUint8List(key, 0, keySize)),
          viewUint8List(key, keySize, blockSize)));
  return applyBlockCipher(cipher, input);
}

Uint8List bcryptHash(Uint8List pass, Uint8List salt) {
  throw FormatException('bcryptHash not implemented');
}

Uint8List bcryptPbkdf(
    Uint8List password, Uint8List salt, int length, int rounds) {
  throw FormatException('bcryptPbkdf not implemented');
}
