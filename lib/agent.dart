// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:typed_data';

import 'package:dartssh/protocol.dart';
import 'package:dartssh/serializable.dart';
import 'package:dartssh/ssh.dart';
import 'package:dartssh/transport.dart';

/// Mixin providing SSH Agent forwarding.
mixin SSHAgentForwarding on SSHTransport {
  /// Frames SSH Agent [channel] data into packets.
  void handleAgentRead(Channel channel, Uint8List msg) =>
      dispatchAgentRead(channel, msg, handleAgentPacket);

  static void dispatchAgentRead(
      Channel channel, Uint8List msg, ChannelInputCallback handleAgentPacket) {
    channel.buf.add(msg);
    while (channel.buf.data.length > 4) {
      SerializableInput input = SerializableInput(channel.buf.data);
      int agentPacketLen = input.getUint32();
      if (input.remaining < agentPacketLen) break;
      handleAgentPacket(
          channel,
          SerializableInput(
              input.viewOffset(input.offset, input.offset + agentPacketLen)));
      channel.buf.flush(agentPacketLen + 4);
    }
  }

  // Dispatches SSH Agent messages to handlers.
  void handleAgentPacket(Channel channel, SerializableInput agentPacketS) {
    int agentPacketId = agentPacketS.getUint8();
    switch (agentPacketId) {
      case AGENTC_REQUEST_IDENTITIES.ID:
        handleAGENTC_REQUEST_IDENTITIES(channel);
        break;

      case AGENTC_SIGN_REQUEST.ID:
        handleAGENTC_SIGN_REQUEST(
            channel, AGENTC_SIGN_REQUEST()..deserialize(agentPacketS));
        break;

      default:
        if (print != null) {
          print('$hostport: unknown agent packet number: $agentPacketId');
        }
        break;
    }
  }

  /// Responds with any identities we're forwarding.
  void handleAGENTC_REQUEST_IDENTITIES(Channel channel) {
    if (tracePrint != null) {
      tracePrint('$hostport: agent channel: AGENTC_REQUEST_IDENTITIES');
    }
    AGENT_IDENTITIES_ANSWER reply = AGENT_IDENTITIES_ANSWER();
    if (identity != null) {
      reply.keys = identity.getRawPublicKeyList();
    }
    sendToChannel(channel, reply.toRaw());
  }

  /// Signs challenge authenticating a descendent channel.
  void handleAGENTC_SIGN_REQUEST(Channel channel, AGENTC_SIGN_REQUEST msg) {
    if (tracePrint != null) {
      tracePrint('$hostport: agent channel: AGENTC_SIGN_REQUEST');
    }
    SerializableInput keyStream = SerializableInput(msg.key);
    String keyType = deserializeString(keyStream);
    Uint8List sig =
        identity.signMessage(Key.id(keyType), msg.data, getSecureRandom());
    if (sig != null) {
      sendToChannel(channel, AGENT_SIGN_RESPONSE(sig).toRaw());
    } else {
      sendToChannel(channel, AGENT_FAILURE().toRaw());
    }
  }
}

/// https://tools.ietf.org/html/draft-miller-ssh-agent-03#section-3
abstract class AgentMessage extends Serializable {
  int id;
  AgentMessage(this.id);

  Uint8List toRaw({Endian endian = Endian.big}) {
    Uint8List buffer = Uint8List(5 + serializedSize);
    SerializableOutput output = SerializableOutput(buffer);
    output.addUint32(buffer.length - 4);
    output.addUint8(id);
    serialize(output);
    if (!output.done) {
      throw FormatException('${output.offset}/${output.buffer.length}');
    }
    return buffer;
  }
}

/// https://tools.ietf.org/html/draft-miller-ssh-agent-03#section-4.1
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

/// https://tools.ietf.org/html/draft-miller-ssh-agent-03#section-4.4
class AGENTC_REQUEST_IDENTITIES extends AgentMessage {
  static const int ID = 11;
  AGENTC_REQUEST_IDENTITIES() : super(ID);

  @override
  int get serializedHeaderSize => 0;

  @override
  int get serializedSize => serializedHeaderSize;

  @override
  void deserialize(SerializableInput input) {}

  @override
  void serialize(SerializableOutput output) {}
}

/// https://tools.ietf.org/html/draft-miller-ssh-agent-03#section-4.4
class AGENT_IDENTITIES_ANSWER extends AgentMessage {
  static const int ID = 12;
  List<MapEntry<Uint8List, String>> keys = List<MapEntry<Uint8List, String>>();
  AGENT_IDENTITIES_ANSWER() : super(ID);

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize => keys.fold(
      serializedHeaderSize, (v, e) => v + 8 + e.key.length + e.value.length);

  @override
  void deserialize(SerializableInput input) {
    keys.clear();
    int length = input.getUint32();
    for (int i = 0; i < length; i++) {
      Uint8List key = deserializeStringBytes(input);
      keys.add(MapEntry<Uint8List, String>(key, deserializeString(input)));
    }
  }

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(keys.length);
    for (MapEntry<Uint8List, String> key in keys) {
      serializeString(output, key.key);
      serializeString(output, key.value);
    }
  }
}

/// https://tools.ietf.org/html/draft-miller-ssh-agent-03#section-4.5
class AGENTC_SIGN_REQUEST extends AgentMessage {
  static const int ID = 13;
  Uint8List key, data;
  int flags;
  AGENTC_SIGN_REQUEST([this.key, this.data, this.flags = 0]) : super(ID);

  @override
  int get serializedHeaderSize => 4 * 3;

  @override
  int get serializedSize => serializedHeaderSize + key.length + data.length;

  @override
  void deserialize(SerializableInput input) {
    key = deserializeStringBytes(input);
    data = deserializeStringBytes(input);
    flags = input.getUint32();
  }

  @override
  void serialize(SerializableOutput output) {
    serializeString(output, key);
    serializeString(output, data);
    output.addUint32(flags);
  }
}

/// On success, the agent shall reply with:
class AGENT_SIGN_RESPONSE extends AgentMessage {
  static const int ID = 14;
  Uint8List sig;
  AGENT_SIGN_RESPONSE([this.sig]) : super(ID);

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize => serializedHeaderSize + sig.length;

  @override
  void deserialize(SerializableInput input) =>
      sig = deserializeStringBytes(input);

  @override
  void serialize(SerializableOutput output) => serializeString(output, sig);
}
