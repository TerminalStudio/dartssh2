// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

// ignore_for_file: camel_case_types, constant_identifier_names

import 'dart:math';
import 'dart:typed_data';

import 'package:dartssh2/bigint.dart';
import 'package:dartssh2/serializable.dart';

/// Rounds [input] up to the next [n]th, if necessary.
int nextMultipleOfN(int input, int n) =>
    (input % n != 0) ? (input ~/ n + 1) * n : input;

/// mpint: https://www.ietf.org/rfc/rfc4251.txt
int mpIntLength(BigInt x) => x.bitLength ~/ 8 + 1;

/// mpint: https://www.ietf.org/rfc/rfc4251.txt
void serializeMpInt(SerializableOutput output, BigInt x) {
  if (x.sign < 0) throw FormatException('Negative BigInt not supported');
  final xBytes = x == BigInt.zero ? Uint8List(0) : encodeBigInt(x);
  output.addUint32(xBytes.length);
  output.addBytes(xBytes);
}

/// mpint: https://www.ietf.org/rfc/rfc4251.txt
BigInt deserializeMpInt(SerializableInput input) =>
    decodeBigIntWithSign(1, deserializeStringBytes(input));

/// string: https://www.ietf.org/rfc/rfc4251.txt
void serializeString(SerializableOutput output, dynamic x) {
  output.addUint32(x.length);
  output.addBytes(x is String ? Uint8List.fromList(x.codeUnits) : x);
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

/// Returns at least [n] random bits.
Uint8List randBits(Random generator, int n) =>
    randBytes(generator, (n + 7) ~/ 8);

/// SSH protocol frame.
class BinaryPacket {
  static const int headerSize = 5;
  final int length, padding;
  BinaryPacket(Uint8List packet) : this.deserialize(SerializableInput(packet));
  BinaryPacket.deserialize(SerializableInput input)
      : length = input.getUint32(),
        padding = input.getUint8();
}

/// Binary Packet Protocol. https://tools.ietf.org/html/rfc4253#section-6
abstract class SSHMessage extends Serializable {
  int id;
  SSHMessage(this.id);

  Uint8List toBytes(dynamic zlib, Random random, int blockSize) {
    Uint8List payload = Uint8List(serializedSize + 1);
    SerializableOutput output = SerializableOutput(payload);
    output.addUint8(id);
    serialize(output);
    if (!output.done) {
      throw FormatException('${output.offset}/${output.buffer.length}');
    }
    return toPacket(
        zlib != null ? zlib.convert(payload) : payload, random, blockSize);
  }

  Uint8List toPacket(Uint8List payload, Random random, int blockSize) {
    Uint8List buffer = Uint8List(nextMultipleOfN(
      4 + BinaryPacket.headerSize + payload.length,
      max(8, blockSize),
    ));
    SerializableOutput output = SerializableOutput(buffer);
    int padding = buffer.length - BinaryPacket.headerSize - payload.length;
    output.addUint32(buffer.length - 4);
    output.addUint8(padding);
    output.addBytes(payload);
    output.addBytes(randBytes(random, padding));
    if (!output.done) {
      throw FormatException('${output.offset}/${output.buffer.length}');
    }
    return buffer;
  }

  @override
  String toString() {
    return runtimeType.toString();
  }
}

/// This message causes immediate termination of the connection.
class MSG_DISCONNECT extends SSHMessage {
  static const int ID = 1;
  int reasonCode = 0;
  String description = '', language = '';
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
  MSG_IGNORE([this.data = '']) : super(ID);

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize => serializedHeaderSize + data.length;

  @override
  void deserialize(SerializableInput input) => data = deserializeString(input);

  @override
  void serialize(SerializableOutput output) => serializeString(output, data);
}

/// This message is used to transmit information that may help debugging.
class MSG_DEBUG extends SSHMessage {
  static const int ID = 4;
  int alwaysDisplay = 0;
  String message, language;
  MSG_DEBUG([this.message = '', this.language = '']) : super(ID);

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
  void serialize(SerializableOutput output) {
    output.addUint8(alwaysDisplay);
    serializeString(output, message);
    serializeString(output, language);
  }
}

/// After the key exchange, the client requests a service.
/// The service is identified by a name.
class MSG_SERVICE_REQUEST extends SSHMessage {
  static const int ID = 5;
  String? serviceName;
  MSG_SERVICE_REQUEST([this.serviceName]) : super(ID);

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize => serializedHeaderSize + serviceName!.length;

  @override
  void deserialize(SerializableInput input) =>
      serviceName = deserializeString(input);

  @override
  void serialize(SerializableOutput output) =>
      serializeString(output, serviceName);

  @override
  String toString() => '$runtimeType[$serviceName]';
}

/// If the server supports the service (and permits the client to use it),
/// it MUST respond with the following.
class MSG_SERVICE_ACCEPT extends SSHMessage {
  static const int ID = 6;

  MSG_SERVICE_ACCEPT(this.serviceName) : super(ID);

  String? serviceName;

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize => serializedHeaderSize + serviceName!.length;

  @override
  void deserialize(SerializableInput input) =>
      serviceName = deserializeString(input);

  @override
  void serialize(SerializableOutput output) =>
      serializeString(output, serviceName);

  @override
  String toString() => '$runtimeType[$serviceName]';
}

/// Key exchange begins by each side sending the following packet.
/// https://tools.ietf.org/html/rfc4253#section-7.1
class MSG_KEXINIT extends SSHMessage {
  static const int ID = 20;
  Uint8List? cookie;
  String? kexAlgorithms,
      serverHostKeyAlgorithms,
      encryptionAlgorithmsClientToServer,
      encryptionAlgorithmsServerToClient,
      macAlgorithmsClientToServer,
      macAlgorithmsServerToClient,
      compressionAlgorithmsClientToServer,
      compressionAlgorithmsServerToClient,
      languagesClientToServer,
      languagesServerToClient;
  bool? firstKexPacketFollows = false;

  MSG_KEXINIT(
      [this.cookie,
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
      this.firstKexPacketFollows])
      : super(ID);

  @override
  int get serializedHeaderSize => 21 + 10 * 4;

  @override
  int get serializedSize =>
      serializedHeaderSize +
      kexAlgorithms!.length +
      serverHostKeyAlgorithms!.length +
      encryptionAlgorithmsClientToServer!.length +
      encryptionAlgorithmsServerToClient!.length +
      macAlgorithmsClientToServer!.length +
      macAlgorithmsServerToClient!.length +
      compressionAlgorithmsClientToServer!.length +
      compressionAlgorithmsServerToClient!.length +
      languagesClientToServer!.length +
      languagesServerToClient!.length;

  @override
  void serialize(SerializableOutput output) {
    output.addBytes(cookie!);
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
    output.addUint8(firstKexPacketFollows! ? 1 : 0);
    output.addUint32(0);
  }

  @override
  void deserialize(SerializableInput input) {
    cookie = input.getBytes(16);
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
    firstKexPacketFollows = input.getBool();
  }

  @override
  String toString() =>
      'kexAlgorithms:                       $kexAlgorithms,                       \n'
      'serverHostKeyAlgorithms:             $serverHostKeyAlgorithms,             \n'
      'encryptionAlgorithmsClientToServer:  $encryptionAlgorithmsClientToServer,  \n'
      'encryptionAlgorithmsServerToClient:  $encryptionAlgorithmsServerToClient,  \n'
      'macAlgorithmsClientToServer:         $macAlgorithmsClientToServer,         \n'
      'macAlgorithmsServerToClient:         $macAlgorithmsServerToClient,         \n'
      'compressionAlgorithmsClientToServer: $compressionAlgorithmsClientToServer, \n'
      'compressionAlgorithmsServerToClient: $compressionAlgorithmsServerToClient, \n'
      'languagesClientToServer:             $languagesClientToServer,             \n'
      'languagesServerToClient:             $languagesServerToClient,             \n'
      'firstKexPacketFollows:               $firstKexPacketFollows,               \n';
}

/// Key exchange ends by each side sending an SSH_MSG_NEWKEYS message.
/// This message is sent with the old keys and algorithms.  All messages
/// sent after this message MUST use the new keys and algorithms.
/// https://tools.ietf.org/html/rfc4253#section-7.3
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

/// C generates a random number x (1 < x < q) and computes e = g^x mod p.  C sends e to S.
/// https://tools.ietf.org/html/rfc4253#section-8
class MSG_KEXDH_INIT extends SSHMessage {
  static const int ID = 30;
  BigInt? e;
  MSG_KEXDH_INIT([this.e]) : super(ID);

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize => serializedHeaderSize + mpIntLength(e!);

  @override
  void serialize(SerializableOutput output) => serializeMpInt(output, e!);

  @override
  void deserialize(SerializableInput input) => e = deserializeMpInt(input);
}

/// S generates a random number y (0 < y < q) and computes f = g^y mod p.
/// S receives e.  It computes K = e^y mod p and H.
class MSG_KEXDH_REPLY extends SSHMessage {
  static const int ID = 31;
  Uint8List? kS, hSig;
  BigInt? f;
  MSG_KEXDH_REPLY([this.f, this.kS, this.hSig]) : super(ID);

  @override
  int get serializedHeaderSize => 4 * 3;

  @override
  int get serializedSize =>
      serializedHeaderSize + mpIntLength(f!) + kS!.length + hSig!.length;

  @override
  void serialize(SerializableOutput output) {
    serializeString(output, kS);
    serializeMpInt(output, f!);
    serializeString(output, hSig);
  }

  @override
  void deserialize(SerializableInput input) {
    kS = deserializeStringBytes(input);
    f = deserializeMpInt(input);
    hSig = deserializeStringBytes(input);
  }
}

/// C sends "min || n || max" to S, indicating the minimal acceptable group size, the
/// preferred size of the group, and the maximal group size in bits the client will accept.
/// https://tools.ietf.org/html/rfc4419
class MSG_KEX_DH_GEX_REQUEST extends SSHMessage {
  static const int ID = 34;
  int? minN, maxN, n;
  MSG_KEX_DH_GEX_REQUEST([this.minN, this.maxN, this.n]) : super(ID);

  @override
  int get serializedHeaderSize => 4 * 3;

  @override
  int get serializedSize => serializedHeaderSize;

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(minN!);
    output.addUint32(n!);
    output.addUint32(maxN!);
  }

  @override
  void deserialize(SerializableInput input) {
    minN = input.getUint32();
    n = input.getUint32();
    maxN = input.getUint32();
  }
}

/// S finds a group that best matches the client's request, and sends "p || g" to C.
class MSG_KEX_DH_GEX_GROUP extends SSHMessage {
  static const int ID = 31;
  BigInt? p, g;
  MSG_KEX_DH_GEX_GROUP([this.p, this.g]) : super(ID);

  @override
  int get serializedHeaderSize => 4 * 2;

  @override
  int get serializedSize =>
      serializedHeaderSize + mpIntLength(p!) + mpIntLength(g!);

  @override
  void serialize(SerializableOutput output) {
    serializeMpInt(output, p!);
    serializeMpInt(output, g!);
  }

  @override
  void deserialize(SerializableInput input) {
    p = deserializeMpInt(input);
    g = deserializeMpInt(input);
  }
}

/// C generates a random number x, where 1 < x < (p-1)/2.
/// It computes e = g^x mod p, and sends "e" to S.
class MSG_KEX_DH_GEX_INIT extends MSG_KEXDH_INIT {
  static const int ID = 32;

  MSG_KEX_DH_GEX_INIT([BigInt? e]) : super(e) {
    id = ID;
  }
}

/// S generates a random number y, where 0 < y < (p-1)/2, and computes
/// f = g^y mod p.  S receives "e".  It computes K = e^y mod p, and H.
class MSG_KEX_DH_GEX_REPLY extends MSG_KEXDH_REPLY {
  static const int ID = 33;

  MSG_KEX_DH_GEX_REPLY([BigInt? f, Uint8List? kS, Uint8List? hSig])
      : super(f, kS, hSig) {
    id = ID;
  }
}

/// Client generates ephemeral key pair.
/// https://tools.ietf.org/html/rfc5656#section-4
class MSG_KEX_ECDH_INIT extends SSHMessage {
  static const int ID = 30;
  Uint8List? qC;
  MSG_KEX_ECDH_INIT([this.qC]) : super(ID);

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize => serializedHeaderSize + qC!.length;

  @override
  void serialize(SerializableOutput output) => serializeString(output, qC);

  @override
  void deserialize(SerializableInput input) =>
      qC = deserializeStringBytes(input);
}

/// Server generates ephemeral key pair, computes shared secret, and
/// generate and signs exchange hash.
/// https://datatracker.ietf.org/doc/html/rfc4253#section-8
class MSG_KEX_ECDH_REPLY extends SSHMessage {
  static const int ID = 31;

  MSG_KEX_ECDH_REPLY([this.qS, this.kS, this.hSig]) : super(ID);

  /// server public host key and certificates (K_S)
  Uint8List? kS;

  /// S generates a random number y (0 < y < q) and computes f = g^y mod p
  Uint8List? qS;

  /// K = e^y mod p,
  /// H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
  Uint8List? hSig;

  @override
  int get serializedHeaderSize => 4 * 3;

  @override
  int get serializedSize =>
      serializedHeaderSize + kS!.length + qS!.length + hSig!.length;

  @override
  void serialize(SerializableOutput output) {
    serializeString(output, kS);
    serializeString(output, qS);
    serializeString(output, hSig);
  }

  @override
  void deserialize(SerializableInput input) {
    kS = deserializeStringBytes(input);
    qS = deserializeStringBytes(input);
    hSig = deserializeStringBytes(input);
  }
}

/// https://tools.ietf.org/html/rfc4252#section-5
class MSG_USERAUTH_REQUEST extends SSHMessage {
  static const int ID = 50;

  MSG_USERAUTH_REQUEST([
    this.userName,
    this.serviceName,
    this.methodName,
    this.algoName,
    this.secret,
    this.sig,
  ]) : super(ID);

  String? userName, serviceName, methodName, algoName;
  Uint8List? secret, sig;

  @override
  int get serializedHeaderSize => 4 * 3;

  @override
  int get serializedSize {
    int ret = serializedHeaderSize +
        userName!.length +
        serviceName!.length +
        methodName!.length;
    if (methodName == 'publickey') {
      ret += 4 * 3 + 1 + algoName!.length + secret!.length + sig!.length;
    } else if (methodName == 'password') {
      ret += 4 * 1 + 1 + secret!.length;
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
  void deserialize(SerializableInput input) {
    userName = deserializeString(input);
    serviceName = deserializeString(input);
    methodName = deserializeString(input);
    if (methodName == 'publickey') {
      input.getUint8();
      algoName = deserializeString(input);
      secret = deserializeStringBytes(input);
      sig = deserializeStringBytes(input);
    } else if (methodName == 'password') {
      input.getUint8();
      secret = deserializeStringBytes(input);
    } else if (methodName == 'keyboard-interactive') {
      deserializeString(input);
      deserializeString(input);
    }
  }

  @override
  String toString() {
    return 'MSG_USERAUTH_REQUEST[userName=$userName, serviceName=$serviceName, methodName=$methodName';
  }
}

/// If the server rejects the authentication request, it MUST respond with the following:
/// https://tools.ietf.org/html/rfc4252#section-5.1
class MSG_USERAUTH_FAILURE extends SSHMessage {
  static const int ID = 51;
  String authLeft;
  int partialSuccess = 0;
  MSG_USERAUTH_FAILURE([this.authLeft = '']) : super(ID);

  @override
  int get serializedHeaderSize => 5;

  @override
  int get serializedSize => serializedHeaderSize + authLeft.length;

  @override
  void serialize(SerializableOutput output) {
    serializeString(output, authLeft);
    output.addUint8(partialSuccess);
  }

  @override
  void deserialize(SerializableInput input) {
    authLeft = deserializeString(input);
    partialSuccess = input.getUint8();
  }
}

/// When the server accepts authentication, it MUST respond with the following:
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

/// https://tools.ietf.org/html/rfc4256#section-3.1
class MSG_USERAUTH_INFO_REQUEST extends SSHMessage {
  static const int ID = 60;

  MSG_USERAUTH_INFO_REQUEST() : super(ID);

  late List<MapEntry<String, int>> prompts;

  late String name, instruction, language;

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
    prompts = <MapEntry<String, int>>[];
    for (int i = 0; i < numPrompts; i++) {
      prompts.add(
          MapEntry<String, int>(deserializeString(input), input.getUint8()));
    }
  }
}

/// https://tools.ietf.org/html/rfc4256#section-3.4
class MSG_USERAUTH_INFO_RESPONSE extends SSHMessage {
  static const int ID = 61;

  MSG_USERAUTH_INFO_RESPONSE([this.response]) : super(ID);

  List<Uint8List?>? response;

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize =>
      response!.fold(serializedHeaderSize, (v, e) => v + 4 + e!.length);

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(response!.length);
    for (Uint8List? r in response!) {
      serializeString(output, r);
    }
  }

  @override
  void deserialize(SerializableInput input) {}

  @override
  String toString() {
    return 'MSG_USERAUTH_INFO_RESPONSE[response=$response]';
  }
}

/// https://tools.ietf.org/html/rfc4254#section-4
class MSG_GLOBAL_REQUEST extends SSHMessage {
  static const int ID = 80;
  late String request;
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

/// https://tools.ietf.org/html/rfc4254#section-7.1
class MSG_GLOBAL_REQUEST_TCPIP extends SSHMessage {
  static const int ID = 80;
  String request = 'tcpip-forward', addr;
  int? port, wantReply = 0;
  MSG_GLOBAL_REQUEST_TCPIP(this.addr, this.port) : super(ID);

  @override
  int get serializedHeaderSize => 4 * 3 + 1;

  @override
  int get serializedSize => serializedHeaderSize + request.length + addr.length;

  @override
  void serialize(SerializableOutput output) {
    serializeString(output, request);
    output.addUint8(wantReply!);
    serializeString(output, addr);
    output.addUint32(port!);
  }

  @override
  void deserialize(SerializableInput input) {
    request = deserializeString(input);
    wantReply = input.getUint8();
    addr = deserializeString(input);
    port = input.getUint32();
  }
}

/// https://tools.ietf.org/html/rfc4254#section-5.1
class MSG_CHANNEL_OPEN extends SSHMessage {
  static const int ID = 90;
  String? channelType;
  int? senderChannel = 0, initialWinSize = 0, maximumPacketSize = 0;
  MSG_CHANNEL_OPEN(
      [this.channelType,
      this.senderChannel,
      this.initialWinSize,
      this.maximumPacketSize])
      : super(ID);

  @override
  int get serializedHeaderSize => 4 * 4;

  @override
  int get serializedSize => serializedHeaderSize + channelType!.length;

  @override
  void serialize(SerializableOutput output) {
    serializeString(output, channelType);
    output.addUint32(senderChannel!);
    output.addUint32(initialWinSize!);
    output.addUint32(maximumPacketSize!);
  }

  @override
  void deserialize(SerializableInput input) {
    channelType = deserializeString(input);
    senderChannel = input.getUint32();
    initialWinSize = input.getUint32();
    maximumPacketSize = input.getUint32();
  }
}

/// https://tools.ietf.org/html/rfc4254#section-7.2
class MSG_CHANNEL_OPEN_TCPIP extends SSHMessage {
  static const int ID = 90;
  String? channelType, srcHost, dstHost;
  int? senderChannel = 0,
      initialWinSize = 0,
      maximumPacketSize = 0,
      srcPort = 0,
      dstPort = 0;
  MSG_CHANNEL_OPEN_TCPIP(
      [this.channelType,
      this.senderChannel,
      this.initialWinSize,
      this.maximumPacketSize,
      this.dstHost,
      this.dstPort,
      this.srcHost,
      this.srcPort])
      : super(ID);

  @override
  int get serializedHeaderSize => 8 * 4;

  @override
  int get serializedSize =>
      serializedHeaderSize +
      channelType!.length +
      srcHost!.length +
      dstHost!.length;

  @override
  void serialize(SerializableOutput output) {
    serializeString(output, channelType);
    output.addUint32(senderChannel!);
    output.addUint32(initialWinSize!);
    output.addUint32(maximumPacketSize!);
    serializeString(output, dstHost);
    output.addUint32(dstPort!);
    serializeString(output, srcHost);
    output.addUint32(srcPort!);
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

/// The remote side then decides whether it can open the channel, and
/// responds with either SSH_MSG_CHANNEL_OPEN_CONFIRMATION or SSH_MSG_CHANNEL_OPEN_FAILURE.
class MSG_CHANNEL_OPEN_CONFIRMATION extends SSHMessage {
  static const int ID = 91;

  MSG_CHANNEL_OPEN_CONFIRMATION([
    this.recipientChannel,
    this.senderChannel,
    this.initialWinSize,
    this.maximumPacketSize,
  ]) : super(ID);

  int? recipientChannel;
  int? senderChannel;
  int? initialWinSize;
  int? maximumPacketSize;

  @override
  int get serializedHeaderSize => 4 * 4;

  @override
  int get serializedSize => serializedHeaderSize;

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(recipientChannel!);
    output.addUint32(senderChannel!);
    output.addUint32(initialWinSize!);
    output.addUint32(maximumPacketSize!);
  }

  @override
  void deserialize(SerializableInput input) {
    recipientChannel = input.getUint32();
    senderChannel = input.getUint32();
    initialWinSize = input.getUint32();
    maximumPacketSize = input.getUint32();
  }
}

/// The client MAY show the 'description' string to the user.
class MSG_CHANNEL_OPEN_FAILURE extends SSHMessage {
  static const int ID = 92;

  MSG_CHANNEL_OPEN_FAILURE(
      [this.recipientChannel, this.reason, this.description, this.language])
      : super(ID);

  int? recipientChannel = 0, reason = 0;
  String? description, language;

  @override
  int get serializedHeaderSize => 4 * 4;

  @override
  int get serializedSize =>
      serializedHeaderSize + description!.length + language!.length;

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(recipientChannel!);
    output.addUint32(reason!);
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

/// The window size specifies how many bytes the other party can send
/// before it must wait for the window to be adjusted.
class MSG_CHANNEL_WINDOW_ADJUST extends SSHMessage {
  static const int ID = 93;
  int? recipientChannel, bytesToAdd;
  MSG_CHANNEL_WINDOW_ADJUST([this.recipientChannel = 0, this.bytesToAdd = 0])
      : super(ID);

  @override
  int get serializedHeaderSize => 4 * 2;

  @override
  int get serializedSize => serializedHeaderSize;

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(recipientChannel!);
    output.addUint32(bytesToAdd!);
  }

  @override
  void deserialize(SerializableInput input) {
    recipientChannel = input.getUint32();
    bytesToAdd = input.getUint32();
  }
}

/// https://tools.ietf.org/html/rfc4254#section-5.2
class MSG_CHANNEL_DATA extends SSHMessage {
  static const int ID = 94;
  int? recipientChannel;
  Uint8List? data;
  MSG_CHANNEL_DATA([this.recipientChannel, this.data]) : super(ID);

  @override
  int get serializedHeaderSize => 4 * 2;

  @override
  int get serializedSize => serializedHeaderSize + data!.length;

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(recipientChannel!);
    serializeString(output, data);
  }

  @override
  void deserialize(SerializableInput input) {
    recipientChannel = input.getUint32();
    data = deserializeStringBytes(input);
  }
}

/// When a party will no longer send more data to a channel, it SHOULD send SSH_MSG_CHANNEL_EOF.
class MSG_CHANNEL_EOF extends SSHMessage {
  static const int ID = 96;
  int? recipientChannel;
  MSG_CHANNEL_EOF([this.recipientChannel = 0]) : super(ID);

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize => serializedHeaderSize;

  @override
  void serialize(SerializableOutput output) =>
      output.addUint32(recipientChannel!);

  @override
  void deserialize(SerializableInput input) =>
      recipientChannel = input.getUint32();
}

/// When either party wishes to terminate the channel, it sends SSH_MSG_CHANNEL_CLOSE.
/// https://tools.ietf.org/html/rfc4254#section-5.3
class MSG_CHANNEL_CLOSE extends SSHMessage {
  static const int ID = 97;
  int? recipientChannel;
  MSG_CHANNEL_CLOSE([this.recipientChannel = 0]) : super(ID);

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize => serializedHeaderSize;

  @override
  void serialize(SerializableOutput output) =>
      output.addUint32(recipientChannel!);

  @override
  void deserialize(SerializableInput input) =>
      recipientChannel = input.getUint32();
}

/// Channel-Specific Requests https://tools.ietf.org/html/rfc4254#section-5.4
class MSG_CHANNEL_REQUEST extends SSHMessage {
  static const int ID = 98;
  int? recipientChannel = 0,
      width = 0,
      height = 0,
      pixelWidth = 0,
      pixelHeight = 0;
  bool wantReply = false;
  String? requestType, term, termMode;
  MSG_CHANNEL_REQUEST() : super(ID);
  MSG_CHANNEL_REQUEST.exec(
      this.recipientChannel, this.requestType, this.term, this.wantReply)
      : super(ID);
  MSG_CHANNEL_REQUEST.exit(
      this.recipientChannel, this.requestType, this.width, this.wantReply)
      : super(ID);
  MSG_CHANNEL_REQUEST.ptyReq(this.recipientChannel, this.requestType, Point d,
      Point pd, this.term, this.termMode, this.wantReply)
      : width = d.x as int?,
        height = d.y as int?,
        pixelWidth = pd.x as int?,
        pixelHeight = pd.y as int?,
        super(ID);

  @override
  int get serializedHeaderSize => 4 * 2 + 1;

  @override
  int get serializedSize {
    int ret = serializedHeaderSize + requestType!.length;
    if (requestType == 'pty-req') {
      ret += 4 * 6 + term!.length + termMode!.length;
    } else if (requestType == 'exec') {
      ret += 4 * 1 + term!.length;
    } else if (requestType == 'window-change') {
      ret += 4 * 4;
    }
    return ret;
  }

  @override
  void deserialize(SerializableInput input) {
    recipientChannel = input.getUint32();
    requestType = deserializeString(input);
    wantReply = input.getUint8() != 0;
  }

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(recipientChannel!);
    serializeString(output, requestType);
    output.addUint8(wantReply ? 1 : 0);
    if (requestType == 'pty-req') {
      serializeString(output, term);
      output.addUint32(width!);
      output.addUint32(height!);
      output.addUint32(pixelWidth!);
      output.addUint32(pixelHeight!);
      serializeString(output, termMode);
    } else if (requestType == 'exec') {
      serializeString(output, term);
    } else if (requestType == 'window-change') {
      output.addUint32(width!);
      output.addUint32(height!);
      output.addUint32(pixelWidth!);
      output.addUint32(pixelHeight!);
    } else if (requestType == 'exit-status') {
      output.addUint32(width!);
    }
  }
}

/// If 'want reply' is FALSE, no response will be sent to the request. Otherwise,
/// the recipient responds with either SSH_MSG_CHANNEL_SUCCESS, or SSH_MSG_CHANNEL_FAILURE.
class MSG_CHANNEL_SUCCESS extends SSHMessage {
  static const int ID = 99;
  int? recipientChannel;
  MSG_CHANNEL_SUCCESS([this.recipientChannel]) : super(ID);

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize => serializedHeaderSize;

  @override
  void serialize(SerializableOutput output) =>
      output.addUint32(recipientChannel!);

  @override
  void deserialize(SerializableInput input) =>
      recipientChannel = input.getUint32();
}

/// These messages do not consume window space and can be sent even if no window space is available.
class MSG_CHANNEL_FAILURE extends SSHMessage {
  static const int ID = 100;
  int? recipientChannel;
  MSG_CHANNEL_FAILURE([this.recipientChannel]) : super(ID);

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize => serializedHeaderSize;

  @override
  void serialize(SerializableOutput output) =>
      output.addUint32(recipientChannel!);

  @override
  void deserialize(SerializableInput input) =>
      recipientChannel = input.getUint32();
}
