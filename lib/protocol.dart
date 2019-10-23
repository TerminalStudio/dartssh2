// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/src/utils.dart';

import 'package:dartssh/ssh.dart';
import 'package:dartssh/serializable.dart';

const int binaryPacketHeaderSize = 5;

int nextMultipleOfN(int input, int n) =>
    (input % n != 0) ? (input ~/ n + 1) * n : input;

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

/// Returns [n] random bytes.
Uint8List randBytes(Random generator, int n) {
  final Uint8List random = Uint8List(n);
  for (int i = 0; i < random.length; i++) {
    random[i] = generator.nextInt(255);
  }
  return random;
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

/// Binary Packet Protocol.
abstract class SSHMessage extends Serializable {
  int id;
  SSHMessage(this.id);

  Uint8List toBytes(ZLibEncoder zlib, Random random, int blockSize) {
    Uint8List payload = Uint8List(serializedSize + 1);
    SerializableOutput output = SerializableOutput(payload);
    output.addUint8(id);
    serialize(output);
    assert(output.done);
    return toPacket(
        zlib != null ? zlib.convert(payload) : payload, random, blockSize);
  }

  Uint8List toPacket(Uint8List payload, Random random, int blockSize) {
    Uint8List buffer = Uint8List(nextMultipleOfN(
        4 + binaryPacketHeaderSize + payload.length, max(8, blockSize)));
    SerializableOutput output = SerializableOutput(buffer);
    int padding = buffer.length - binaryPacketHeaderSize - payload.length;
    output.addUint32(buffer.length - 4);
    output.addUint8(padding);
    output.addBytes(payload);
    output.addBytes(randBytes(random, padding));
    assert(output.done);
    return buffer;
  }
}

/// This message causes immediate termination of the connection.
class MSG_DISCONNECT extends SSHMessage {
  static const int ID = 1;
  int reasonCode = 0;
  String description, language;
  MSG_DISCONNECT() : super(ID);

  @override
  int get serializedHeaderSize => 4 + 2 * 4;

  @override
  int get serializedSize =>
      serializedHeaderSize + description.length + language.length;

  @override
  void deserialize(SerializableInput input) {
    reasonCode = input.getUint32();
    description = deserializeString(input);
    language = deserializeString(input);
  }

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(reasonCode);
    serializeString(output, description);
    serializeString(output, language);
  }
}

/// All implementations MUST understand (and ignore) this message at any
/// time (after receiving the identification string).
class MSG_IGNORE extends SSHMessage {
  static const int ID = 2;
  String data;
  MSG_IGNORE() : super(ID);

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize => serializedHeaderSize + data.length;

  @override
  void deserialize(SerializableInput input) => data = deserializeString(input);

  @override
  void serialize(SerializableOutput output) {}
}

/// This message is used to transmit information that may help debugging.
class MSG_DEBUG extends SSHMessage {
  static const int ID = 4;
  int alwaysDisplay = 0;
  String message, language;
  MSG_DEBUG() : super(ID);

  @override
  int get serializedHeaderSize => 1 + 2 * 4;

  @override
  int get serializedSize =>
      serializedHeaderSize + message.length + language.length;

  @override
  void deserialize(SerializableInput input) {
    alwaysDisplay = input.getUint8();
    message = deserializeString(input);
    language = deserializeString(input);
  }

  @override
  void serialize(SerializableOutput output) {}
}

/// After the key exchange, the client requests a service.
/// The service is identified by a name.
class MSG_SERVICE_REQUEST extends SSHMessage {
  static const int ID = 5;
  String serviceName;
  MSG_SERVICE_REQUEST(this.serviceName) : super(ID);

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize => serializedHeaderSize + serviceName.length;

  @override
  void deserialize(SerializableInput input) =>
      serviceName = deserializeString(input);

  @override
  void serialize(SerializableOutput output) =>
      serializeString(output, serviceName);
}

/// If the server supports the service (and permits the client to use it),
/// it MUST respond with the following.
class MSG_SERVICE_ACCEPT extends SSHMessage {
  static const int ID = 6;
  String serviceName;
  MSG_SERVICE_ACCEPT(this.serviceName) : super(ID);

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize => serializedHeaderSize + serviceName.length;

  @override
  void deserialize(SerializableInput input) =>
      serviceName = deserializeString(input);

  @override
  void serialize(SerializableOutput output) =>
      serializeString(output, serviceName);
}

/// Key exchange begins by each side sending the following packet.
class MSG_KEXINIT extends SSHMessage {
  static const int ID = 20;
  String cookie,
      kexAlgorithms,
      serverHostKeyAlgorithms,
      encryptionAlgorithmsClientToServer,
      encryptionAlgorithmsServerToClient,
      macAlgorithmsClientToServer,
      macAlgorithmsServerToClient,
      compressionAlgorithmsClientToServer,
      compressionAlgorithmsServerToClient,
      languagesClientToServer,
      languagesServerToClient;
  int firstKexPacketFollows = 0;

  MSG_KEXINIT.blank() : super(ID);
  MSG_KEXINIT(
      this.cookie,
      this.kexAlgorithms,
      this.serverHostKeyAlgorithms,
      this.encryptionAlgorithmsClientToServer,
      this.encryptionAlgorithmsServerToClient,
      this.macAlgorithmsClientToServer,
      this.macAlgorithmsServerToClient,
      this.compressionAlgorithmsClientToServer,
      this.compressionAlgorithmsServerToClient,
      this.languagesClientToServer,
      this.languagesServerToClient,
      this.firstKexPacketFollows)
      : super(ID);

  @override
  int get serializedHeaderSize => 21 + 10 * 4;

  @override
  int get serializedSize =>
      serializedHeaderSize +
      kexAlgorithms.length +
      serverHostKeyAlgorithms.length +
      encryptionAlgorithmsClientToServer.length +
      encryptionAlgorithmsServerToClient.length +
      macAlgorithmsClientToServer.length +
      macAlgorithmsServerToClient.length +
      compressionAlgorithmsClientToServer.length +
      compressionAlgorithmsServerToClient.length +
      languagesClientToServer.length +
      languagesServerToClient.length;

  @override
  void serialize(SerializableOutput output) {
    output.addBytes(cookie.codeUnits);
    serializeString(output, kexAlgorithms);
    serializeString(output, serverHostKeyAlgorithms);
    serializeString(output, encryptionAlgorithmsClientToServer);
    serializeString(output, encryptionAlgorithmsServerToClient);
    serializeString(output, macAlgorithmsClientToServer);
    serializeString(output, macAlgorithmsServerToClient);
    serializeString(output, compressionAlgorithmsClientToServer);
    serializeString(output, compressionAlgorithmsServerToClient);
    serializeString(output, languagesClientToServer);
    serializeString(output, languagesServerToClient);
    output.addUint8(firstKexPacketFollows);
    output.addUint32(0);
  }

  @override
  void deserialize(SerializableInput input) {
    cookie = String.fromCharCodes(input.getBytes(16));
    kexAlgorithms = deserializeString(input);
    serverHostKeyAlgorithms = deserializeString(input);
    encryptionAlgorithmsClientToServer = deserializeString(input);
    encryptionAlgorithmsServerToClient = deserializeString(input);
    macAlgorithmsClientToServer = deserializeString(input);
    macAlgorithmsServerToClient = deserializeString(input);
    compressionAlgorithmsClientToServer = deserializeString(input);
    compressionAlgorithmsServerToClient = deserializeString(input);
    languagesClientToServer = deserializeString(input);
    languagesServerToClient = deserializeString(input);
    firstKexPacketFollows = input.getUint8();
  }

  String toString() =>
      'kexAlgorithms:                       $kexAlgorithms,                       \n' +
      'serverHostKeyAlgorithms:             $serverHostKeyAlgorithms,             \n' +
      'encryptionAlgorithmsClientToServer:  $encryptionAlgorithmsClientToServer,  \n' +
      'encryptionAlgorithmsServerToClient:  $encryptionAlgorithmsServerToClient,  \n' +
      'macAlgorithmsClientToServer:         $macAlgorithmsClientToServer,         \n' +
      'macAlgorithmsServerToClient:         $macAlgorithmsServerToClient,         \n' +
      'compressionAlgorithmsClientToServer: $compressionAlgorithmsClientToServer, \n' +
      'compressionAlgorithmsServerToClient: $compressionAlgorithmsServerToClient, \n' +
      'languagesClientToServer:             $languagesClientToServer,             \n' +
      'languagesServerToClient:             $languagesServerToClient,             \n' +
      'firstKexPacketFollows:               $firstKexPacketFollows,               \n';
}

/// Key exchange ends by each side sending an SSH_MSG_NEWKEYS message.
/// This message is sent with the old keys and algorithms.  All messages
/// sent after this message MUST use the new keys and algorithms.
class MSG_NEWKEYS extends SSHMessage {
  static const int ID = 21;
  MSG_NEWKEYS() : super(ID);

  @override
  int get serializedHeaderSize => 0;

  @override
  int get serializedSize => serializedHeaderSize;

  @override
  void serialize(SerializableOutput output) {}

  @override
  void deserialize(SerializableInput input) {}
}

/// First, the client sends the following.
class MSG_KEXDH_INIT extends SSHMessage {
  static const int ID = 30;
  BigInt e;
  MSG_KEXDH_INIT(this.e) : super(ID);

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize => serializedHeaderSize + mpIntLength(e);

  @override
  void serialize(SerializableOutput output) => serializeMpInt(output, e);

  @override
  void deserialize(SerializableInput input) {}
}

/// The server then responds with the following.
class MSG_KEXDH_REPLY extends SSHMessage {
  static const int ID = 31;
  String kS, hSig;
  BigInt f;
  MSG_KEXDH_REPLY([this.f]) : super(ID);

  @override
  int get serializedHeaderSize => 4 * 3;

  @override
  int get serializedSize =>
      serializedHeaderSize + mpIntLength(f) + kS.length + hSig.length;

  @override
  void serialize(SerializableOutput output) {}

  @override
  void deserialize(SerializableInput input) {
    kS = deserializeString(input);
    f = deserializeMpInt(input);
    hSig = deserializeString(input);
  }
}

class MSG_KEX_DH_GEX_REQUEST extends SSHMessage {
  static const int ID = 34;
  int minN, maxN, n;
  MSG_KEX_DH_GEX_REQUEST(this.minN, this.maxN, this.n) : super(ID);

  @override
  int get serializedHeaderSize => 4 * 3;

  @override
  int get serializedSize => serializedHeaderSize;

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(minN);
    output.addUint32(n);
    output.addUint32(maxN);
  }

  @override
  void deserialize(SerializableInput input) {
    minN = input.getUint32();
    n = input.getUint32();
    maxN = input.getUint32();
  }
}

class MSG_KEX_DH_GEX_GROUP extends SSHMessage {
  static const int ID = 31;
  BigInt p, g;
  MSG_KEX_DH_GEX_GROUP(this.p, this.g) : super(ID);

  @override
  int get serializedHeaderSize => 4 * 2;

  @override
  int get serializedSize =>
      serializedHeaderSize + mpIntLength(p) + mpIntLength(g);

  @override
  void serialize(SerializableOutput output) {}

  @override
  void deserialize(SerializableInput input) {
    p = deserializeMpInt(input);
    g = deserializeMpInt(input);
  }
}

class MSG_KEX_DH_GEX_INIT extends MSG_KEXDH_INIT {
  static const int ID = 32;
  MSG_KEX_DH_GEX_INIT([BigInt e]) : super(e) {
    id = ID;
  }
}

class MSG_KEX_DH_GEX_REPLY extends MSG_KEXDH_REPLY {
  static const int ID = 33;
  MSG_KEX_DH_GEX_REPLY([BigInt f]) : super(f) {
    id = ID;
  }
}

class MSG_KEX_ECDH_INIT extends SSHMessage {
  static const int ID = 30;
  String qC;
  MSG_KEX_ECDH_INIT(this.qC) : super(ID);

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize => serializedHeaderSize + qC.length;

  @override
  void serialize(SerializableOutput output) => serializeString(output, qC);

  @override
  void deserialize(SerializableInput input) => qC = deserializeString(input);
}

class MSG_KEX_ECDH_REPLY extends SSHMessage {
  static const int ID = 31;
  String kS, qS, hSig;
  MSG_KEX_ECDH_REPLY() : super(ID);

  @override
  int get serializedHeaderSize => 4 * 3;

  @override
  int get serializedSize =>
      serializedHeaderSize + kS.length + qS.length + hSig.length;

  @override
  void serialize(SerializableOutput output) {
    serializeString(output, kS);
    serializeString(output, qS);
    serializeString(output, hSig);
  }

  @override
  void deserialize(SerializableInput input) {
    kS = deserializeString(input);
    qS = deserializeString(input);
    hSig = deserializeString(input);
  }
}

class MSG_USERAUTH_REQUEST extends SSHMessage {
  static const int ID = 50;
  String userName, serviceName, methodName, algoName, secret, sig;
  MSG_USERAUTH_REQUEST(this.userName, this.serviceName, this.methodName,
      this.algoName, this.secret, this.sig)
      : super(ID);

  @override
  int get serializedHeaderSize => 4 * 3;

  @override
  int get serializedSize {
    int ret = serializedHeaderSize +
        userName.length +
        serviceName.length +
        methodName.length;
    if (methodName == 'publickey') {
      ret += 4 * 3 + 1 + algoName.length + secret.length + sig.length;
    } else if (methodName == 'password') {
      ret += 4 * 1 + 1 + secret.length;
    } else if (methodName == 'keyboard-interactive') {
      ret += 4 * 2;
    }
    return ret;
  }

  @override
  void serialize(SerializableOutput output) {
    serializeString(output, userName);
    serializeString(output, serviceName);
    serializeString(output, methodName);
    if (methodName == 'publickey') {
      output.addUint8(1);
      serializeString(output, algoName);
      serializeString(output, secret);
      serializeString(output, sig);
    } else if (methodName == 'password') {
      output.addUint8(0);
      serializeString(output, secret);
    } else if (methodName == 'keyboard-interactive') {
      serializeString(output, '');
      serializeString(output, '');
    }
  }

  @override
  void deserialize(SerializableInput input) {}
}

class MSG_USERAUTH_FAILURE extends SSHMessage {
  static const int ID = 51;
  String authLeft;
  int partialSuccess = 0;
  MSG_USERAUTH_FAILURE() : super(ID);

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize => serializedHeaderSize + authLeft.length;

  @override
  void serialize(SerializableOutput output) {}

  @override
  void deserialize(SerializableInput input) {
    authLeft = deserializeString(input);
    partialSuccess = input.getUint8();
  }
}

class MSG_USERAUTH_SUCCESS extends SSHMessage {
  static const int ID = 52;
  MSG_USERAUTH_SUCCESS() : super(ID);

  @override
  int get serializedHeaderSize => 0;

  @override
  int get serializedSize => serializedHeaderSize;

  @override
  void serialize(SerializableOutput output) {}

  @override
  void deserialize(SerializableInput input) {}
}

class MSG_USERAUTH_INFO_REQUEST extends SSHMessage {
  static const int ID = 60;
  String name, instruction, language;
  List<MapEntry<String, int>> prompts;
  MSG_USERAUTH_INFO_REQUEST() : super(ID);

  @override
  int get serializedHeaderSize => 4 * 3;

  @override
  int get serializedSize => prompts.fold(
      serializedHeaderSize + name.length + instruction.length + language.length,
      (v, e) => v + 4 + 1 + e.key.length);

  @override
  void serialize(SerializableOutput output) {}

  @override
  void deserialize(SerializableInput input) {
    int numPrompts = 0;
    name = deserializeString(input);
    instruction = deserializeString(input);
    language = deserializeString(input);
    numPrompts = input.getUint32();
    prompts = List<MapEntry<String, int>>();
    for (int i = 0; i < numPrompts; i++) {
      prompts.add(
          MapEntry<String, int>(deserializeString(input), input.getUint8()));
    }
  }
}

class MSG_USERAUTH_INFO_RESPONSE extends SSHMessage {
  static const int ID = 61;
  List<String> response;
  MSG_USERAUTH_INFO_RESPONSE([this.response]) : super(ID);

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize =>
      response.fold(serializedHeaderSize, (v, e) => v + 4 + e.length);

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(response.length);
    for (String r in response) {
      serializeString(output, r);
    }
  }

  @override
  void deserialize(SerializableInput input) {}
}

class MSG_GLOBAL_REQUEST extends SSHMessage {
  static const int ID = 80;
  String request;
  int wantReply = 0;
  MSG_GLOBAL_REQUEST() : super(ID);

  @override
  int get serializedHeaderSize => 4 + 1;

  @override
  int get serializedSize => serializedHeaderSize + request.length;

  @override
  void serialize(SerializableOutput output) {}

  @override
  void deserialize(SerializableInput input) {
    request = deserializeString(input);
    wantReply = input.getUint8();
  }
}

class MSG_GLOBAL_REQUEST_TCPIP extends SSHMessage {
  static const int ID = 80;
  String request = 'tcpip-forward', addr;
  int port, wantReply = 0;
  MSG_GLOBAL_REQUEST_TCPIP(this.addr, this.port) : super(ID);

  @override
  int get serializedHeaderSize => 4 * 3 + 1;

  @override
  int get serializedSize => serializedHeaderSize + request.length + addr.length;

  @override
  void serialize(SerializableOutput output) {
    serializeString(output, request);
    output.addUint8(wantReply);
    serializeString(output, addr);
    output.addUint32(port);
  }

  @override
  void deserialize(SerializableInput input) {
    request = deserializeString(input);
    wantReply = input.getUint8();
    addr = deserializeString(input);
    port = input.getUint32();
  }
}

class MSG_CHANNEL_OPEN extends SSHMessage {
  static const int ID = 90;
  String channelType;
  int senderChannel = 0, initialWinSize = 0, maximumPacketSize = 0;
  MSG_CHANNEL_OPEN.empty() : super(ID);
  MSG_CHANNEL_OPEN(this.channelType, this.senderChannel, this.initialWinSize,
      this.maximumPacketSize)
      : super(ID);

  @override
  int get serializedHeaderSize => 4 * 4;

  @override
  int get serializedSize => serializedHeaderSize + channelType.length;

  @override
  void serialize(SerializableOutput output) {
    serializeString(output, channelType);
    output.addUint32(senderChannel);
    output.addUint32(initialWinSize);
    output.addUint32(maximumPacketSize);
  }

  @override
  void deserialize(SerializableInput input) {
    channelType = deserializeString(input);
    senderChannel = input.getUint32();
    initialWinSize = input.getUint32();
    maximumPacketSize = input.getUint32();
  }
}

class MSG_CHANNEL_OPEN_TCPIP extends SSHMessage {
  static const int ID = 90;
  String channelType, srcHost, dstHost;
  int senderChannel = 0,
      initialWinSize = 0,
      maximumPacketSize = 0,
      srcPort = 0,
      dstPort = 0;
  MSG_CHANNEL_OPEN_TCPIP.empty() : super(ID);
  MSG_CHANNEL_OPEN_TCPIP(
      this.channelType,
      this.senderChannel,
      this.initialWinSize,
      this.maximumPacketSize,
      this.dstHost,
      this.dstPort,
      this.srcHost,
      this.srcPort)
      : super(ID);

  @override
  int get serializedHeaderSize => 8 * 4;

  @override
  int get serializedSize =>
      serializedHeaderSize +
      channelType.length +
      srcHost.length +
      dstHost.length;

  @override
  void serialize(SerializableOutput output) {
    serializeString(output, channelType);
    output.addUint32(senderChannel);
    output.addUint32(initialWinSize);
    output.addUint32(maximumPacketSize);
    serializeString(output, dstHost);
    output.addUint32(dstPort);
    serializeString(output, srcHost);
    output.addUint32(srcPort);
  }

  @override
  void deserialize(SerializableInput input) {
    // Skip MSG_CHANNEL_OPEN prefix
    dstHost = deserializeString(input);
    dstPort = input.getUint32();
    srcHost = deserializeString(input);
    srcPort = input.getUint32();
  }
}

class MSG_CHANNEL_OPEN_CONFIRMATION extends SSHMessage {
  static const int ID = 91;
  int recipientChannel, senderChannel, initialWinSize, maximumPacketSize;
  MSG_CHANNEL_OPEN_CONFIRMATION.empty() : super(ID);
  MSG_CHANNEL_OPEN_CONFIRMATION(this.recipientChannel, this.senderChannel,
      this.initialWinSize, this.maximumPacketSize)
      : super(ID);

  @override
  int get serializedHeaderSize => 4 * 4;

  @override
  int get serializedSize => serializedHeaderSize;

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(recipientChannel);
    output.addUint32(senderChannel);
    output.addUint32(initialWinSize);
    output.addUint32(maximumPacketSize);
  }

  @override
  void deserialize(SerializableInput input) {
    recipientChannel = input.getUint32();
    senderChannel = input.getUint32();
    initialWinSize = input.getUint32();
    maximumPacketSize = input.getUint32();
  }
}

class MSG_CHANNEL_OPEN_FAILURE extends SSHMessage {
  static const int ID = 91;
  int recipientChannel = 0, reason = 0;
  String description, language;
  MSG_CHANNEL_OPEN_FAILURE.blank() : super(ID);
  MSG_CHANNEL_OPEN_FAILURE(
      this.recipientChannel, this.reason, this.description, this.language)
      : super(ID);

  @override
  int get serializedHeaderSize => 4 * 4;

  @override
  int get serializedSize =>
      serializedHeaderSize + description.length + language.length;

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(recipientChannel);
    output.addUint32(reason);
    serializeString(output, description);
    serializeString(output, language);
  }

  @override
  void deserialize(SerializableInput input) {
    recipientChannel = input.getUint32();
    reason = input.getUint32();
    description = deserializeString(input);
    language = deserializeString(input);
  }
}

class MSG_CHANNEL_WINDOW_ADJUST extends SSHMessage {
  static const int ID = 93;
  int recipientChannel, bytesToAdd;
  MSG_CHANNEL_WINDOW_ADJUST([this.recipientChannel = 0, this.bytesToAdd = 0])
      : super(ID);

  @override
  int get serializedHeaderSize => 4 * 2;

  @override
  int get serializedSize => serializedHeaderSize;

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(recipientChannel);
    output.addUint32(bytesToAdd);
  }

  @override
  void deserialize(SerializableInput input) {
    recipientChannel = input.getUint32();
    bytesToAdd = input.getUint32();
  }
}

class MSG_CHANNEL_DATA extends SSHMessage {
  static const int ID = 94;
  int recipientChannel;
  String data;
  MSG_CHANNEL_DATA.blank() : super(ID);
  MSG_CHANNEL_DATA(this.recipientChannel, this.data) : super(ID);

  @override
  int get serializedHeaderSize => 4 * 2;

  @override
  int get serializedSize => serializedHeaderSize + data.length;

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(recipientChannel);
    serializeString(output, data);
  }

  @override
  void deserialize(SerializableInput input) {
    recipientChannel = input.getUint32();
    data = deserializeString(input);
  }
}

class MSG_CHANNEL_EOF extends SSHMessage {
  static const int ID = 96;
  int recipientChannel;
  MSG_CHANNEL_EOF([this.recipientChannel = 0]) : super(ID);

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize => serializedHeaderSize;

  @override
  void serialize(SerializableOutput output) =>
      output.addUint32(recipientChannel);

  @override
  void deserialize(SerializableInput input) =>
      recipientChannel = input.getUint32();
}

class MSG_CHANNEL_CLOSE extends SSHMessage {
  static const int ID = 97;
  int recipientChannel;
  MSG_CHANNEL_CLOSE([this.recipientChannel = 0]) : super(ID);

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize => serializedHeaderSize;

  @override
  void serialize(SerializableOutput output) =>
      output.addUint32(recipientChannel);

  @override
  void deserialize(SerializableInput input) =>
      recipientChannel = input.getUint32();
}

class MSG_CHANNEL_REQUEST extends SSHMessage {
  static const int ID = 98;
  int recipientChannel = 0,
      width = 0,
      height = 0,
      pixelWidth = 0,
      pixelHeight = 0,
      wantReply = 0;
  String requestType, term, termMode;
  MSG_CHANNEL_REQUEST.blank() : super(ID);
  MSG_CHANNEL_REQUEST.exec(
      this.recipientChannel, this.requestType, this.term, this.wantReply)
      : super(ID);
  MSG_CHANNEL_REQUEST.exit(
      this.recipientChannel, this.requestType, this.width, this.wantReply)
      : super(ID);
  MSG_CHANNEL_REQUEST.ptyReq(this.recipientChannel, this.requestType, Point d,
      Point pd, this.term, this.termMode, this.wantReply)
      : width = d.x,
        height = d.y,
        pixelWidth = pd.x,
        pixelHeight = pd.y,
        super(ID);

  @override
  int get serializedHeaderSize => 4 * 2 + 1;

  @override
  int get serializedSize {
    int ret = serializedHeaderSize + requestType.length;
    if (requestType == 'pty-req') {
      ret += 4 * 6 + term.length + termMode.length;
    } else if (requestType == 'exec') {
      ret += 4 * 1 + term.length;
    } else if (requestType == 'window-change') {
      ret += 4 * 4;
    }
    return ret;
  }

  @override
  void deserialize(SerializableInput input) {
    recipientChannel = input.getUint32();
    requestType = deserializeString(input);
    wantReply = input.getUint8();
  }

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(recipientChannel);
    serializeString(output, requestType);
    output.addUint8(wantReply);
    if (requestType == 'pty-req') {
      serializeString(output, term);
      output.addUint32(width);
      output.addUint32(height);
      output.addUint32(pixelWidth);
      output.addUint32(pixelHeight);
      serializeString(output, termMode);
    } else if (requestType == 'exec') {
      serializeString(output, term);
    } else if (requestType == 'window-change') {
      output.addUint32(width);
      output.addUint32(height);
      output.addUint32(pixelWidth);
      output.addUint32(pixelHeight);
    } else if (requestType == 'exit-status') {
      output.addUint32(width);
    }
  }
}

class MSG_CHANNEL_SUCCESS extends SSHMessage {
  static const int ID = 99;
  MSG_CHANNEL_SUCCESS() : super(ID);

  @override
  int get serializedHeaderSize => 0;

  @override
  int get serializedSize => serializedHeaderSize;

  @override
  void serialize(SerializableOutput output) {}

  @override
  void deserialize(SerializableInput input) {}
}

class MSG_CHANNEL_FAILURE extends SSHMessage {
  static const int ID = 100;
  MSG_CHANNEL_FAILURE() : super(ID);

  @override
  int get serializedHeaderSize => 0;

  @override
  int get serializedSize => serializedHeaderSize;

  @override
  void serialize(SerializableOutput output) {}

  @override
  void deserialize(SerializableInput input) {}
}

abstract class AgentMessage extends Serializable {
  int id;
  AgentMessage(this.id);

  Uint8List toRaw() {
    Uint8List buffer = Uint8List(5 + serializedSize);
    SerializableOutput output = SerializableOutput(buffer);
    output.addUint32(buffer.length - 4);
    output.addUint8(id);
    serialize(output);
    assert(output.done);
    return buffer;
  }
}

class AGENT_FAILURE extends AgentMessage {
  static const int ID = 5;
  AGENT_FAILURE() : super(ID);

  @override
  int get serializedHeaderSize => 0;

  @override
  int get serializedSize => serializedHeaderSize;

  @override
  void deserialize(SerializableInput input) {}

  @override
  void serialize(SerializableOutput output) {}
}

class AGENTC_REQUEST_IDENTITIES {
  static const int ID = 11;
}

class AGENT_IDENTITIES_ANSWER extends AgentMessage {
  static const int ID = 12;
  List<MapEntry<String, String>> keys;
  AGENT_IDENTITIES_ANSWER() : super(ID);

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize => keys.fold(
      serializedHeaderSize, (v, e) => v + 8 + e.key.length + e.value.length);

  @override
  void deserialize(SerializableInput input) {}

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(keys.length);
    for (MapEntry<String, String> key in keys) {
      serializeString(output, key.key);
      serializeString(output, key.value);
    }
  }
}

class AGENTC_SIGN_REQUEST extends AgentMessage {
  static const int ID = 13;
  String key, data;
  int flags;
  AGENTC_SIGN_REQUEST() : super(ID);

  @override
  int get serializedHeaderSize => 4 * 3;

  @override
  int get serializedSize => serializedHeaderSize + key.length + data.length;

  @override
  void deserialize(SerializableInput input) {
    key = deserializeString(input);
    data = deserializeString(input);
    flags = input.getUint32();
  }

  @override
  void serialize(SerializableOutput output) {}
}

class AGENT_SIGN_RESPONSE extends AgentMessage {
  static const int ID = 14;
  String sig;
  AGENT_SIGN_RESPONSE(this.sig) : super(ID);

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize => serializedHeaderSize + sig.length;

  @override
  void deserialize(SerializableInput input) => sig = deserializeString(input);

  @override
  void serialize(SerializableOutput output) => serializeString(output, sig);
}
