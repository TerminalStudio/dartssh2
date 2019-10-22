// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:typed_data';

import 'package:pointycastle/src/utils.dart';

import 'package:dartssh/ssh.dart';
import 'package:dartssh/serializable.dart';

/// mpint: https://www.ietf.org/rfc/rfc4251.txt
int mpIntLength(BigInt x) => x.bitLength ~/ 8 + 1;

/// mpint: https://www.ietf.org/rfc/rfc4251.txt
void serializeMpInt(SerializableOutput output, BigInt x) {
  if (x.sign < 0) throw FormatException('Negative BigInt not supported');
  Uint8List xBytes = encodeBigInt(x);
  bool padX = x.bitLength > 0 && x.bitLength % 8 == 0;
  output.addUint32(xBytes.length + (padX ? 1 : 0));
  if (padX) output.addUint8(0);
  output.addBytes(xBytes);
}

/// mpint: https://www.ietf.org/rfc/rfc4251.txt
BigInt deserializeMpInt(SerializableInput input) =>
    decodeBigInt(deserializeStringBytes(input));

/// string: https://www.ietf.org/rfc/rfc4251.txt
int serializedStringLength(dynamic x) => 4 + x.length;

/// string: https://www.ietf.org/rfc/rfc4251.txt
void serializeString(SerializableOutput output, dynamic x) {
  output.addUint32(x.length);
  output.addBytes(x is String ? x.codeUnits : x);
}

/// string: https://www.ietf.org/rfc/rfc4251.txt
String deserializeString(SerializableInput input) =>
    String.fromCharCodes(deserializeStringBytes(input));

/// string: https://www.ietf.org/rfc/rfc4251.txt
Uint8List deserializeStringBytes(SerializableInput input) =>
    input.getBytes(input.getUint32());

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
  Ed25519Key(this.key);

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
  Ed25519Signature(this.sig);

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
