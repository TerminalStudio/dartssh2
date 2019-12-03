// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import "package:pointycastle/api.dart";

import 'package:dartssh/identity.dart';
import 'package:dartssh/kex.dart';
import 'package:dartssh/socket.dart';
import 'package:dartssh/ssh.dart';
import 'package:dartssh/protocol.dart';
import 'package:dartssh/serializable.dart';
import 'package:dartssh/transport.dart';

typedef ChannelRequest = bool Function(SSHServer server, String request);
typedef UserAuthRequest = bool Function(MSG_USERAUTH_REQUEST msg);
typedef GexRequest = MapEntry<BigInt, BigInt> Function(MSG_KEX_DH_GEX_REQUEST);

class SSHServer extends SSHTransport {
  // Parameters
  RemoteForwardCallback directTcpRequest;
  UserAuthRequest userAuthRequest;
  ChannelRequest sessionChannelRequest;
  GexRequest gexRequest;

  SSHServer(Identity hostkey,
      {Uri hostport,
      bool compress = false,
      List<Forward> forwardLocal,
      List<Forward> forwardRemote,
      VoidCallback disconnected,
      ResponseCallback response,
      StringCallback print,
      StringCallback debugPrint,
      StringCallback tracePrint,
      SocketInterface socket,
      Random random,
      SecureRandom secureRandom,
      this.directTcpRequest,
      this.userAuthRequest,
      this.sessionChannelRequest,
      this.gexRequest})
      : super(true,
            identity: hostkey,
            hostport: hostport,
            compress: compress,
            forwardLocal: forwardLocal,
            forwardRemote: forwardRemote,
            disconnected: disconnected,
            response: response,
            print: print,
            debugPrint: debugPrint,
            tracePrint: tracePrint,
            socket: socket,
            random: random,
            secureRandom: secureRandom) {
    onConnected();
  }

  /// Does nothing.  The client initializes Diffie Hellman.
  @override
  void sendDiffileHellmanInit() {}

  @override
  void handlePacket(Uint8List packet) {
    packetId = packetS.getUint8();
    switch (packetId) {
      case MSG_KEXINIT.ID:
        state = state == SSHTransportState.FIRST_KEXINIT
            ? SSHTransportState.FIRST_KEXREPLY
            : SSHTransportState.KEXREPLY;
        handleMSG_KEXINIT(MSG_KEXINIT()..deserialize(packetS), packet);
        break;

      case MSG_KEXDH_INIT.ID:
      case MSG_KEX_DH_GEX_INIT.ID:
        handleMSG_KEXDH_INIT(packetId, packet);
        break;

      case MSG_KEX_DH_GEX_REQUEST.ID:
        handleMSG_KEX_DH_GEX_REQUEST(
            MSG_KEX_DH_GEX_REQUEST()..deserialize(packetS));
        break;

      case MSG_NEWKEYS.ID:
        handleMSG_NEWKEYS();
        break;

      case MSG_SERVICE_REQUEST.ID:
        handleMSG_SERVICE_REQUEST(MSG_SERVICE_REQUEST()..deserialize(packetS));
        break;

      case MSG_USERAUTH_REQUEST.ID:
        handleMSG_USERAUTH_REQUEST(
            MSG_USERAUTH_REQUEST()..deserialize(packetS));
        break;

      case MSG_CHANNEL_OPEN.ID:
        handleMSG_CHANNEL_OPEN(
            MSG_CHANNEL_OPEN()..deserialize(packetS), packetS);
        break;

      case MSG_CHANNEL_REQUEST.ID:
        handleMSG_CHANNEL_REQUEST(MSG_CHANNEL_REQUEST()..deserialize(packetS));
        break;

      case MSG_CHANNEL_OPEN_CONFIRMATION.ID:
        handleMSG_CHANNEL_OPEN_CONFIRMATION(
            MSG_CHANNEL_OPEN_CONFIRMATION()..deserialize(packetS));
        break;

      case MSG_CHANNEL_DATA.ID:
        handleMSG_CHANNEL_DATA(MSG_CHANNEL_DATA()..deserialize(packetS));
        break;

      case MSG_CHANNEL_EOF.ID:
        handleMSG_CHANNEL_EOF(MSG_CHANNEL_EOF()..deserialize(packetS));
        break;

      case MSG_CHANNEL_CLOSE.ID:
        handleMSG_CHANNEL_CLOSE(MSG_CHANNEL_CLOSE()..deserialize(packetS));
        break;

      case MSG_DISCONNECT.ID:
        handleMSG_DISCONNECT(MSG_DISCONNECT()..deserialize(packetS));
        break;

      default:
        if (print != null) {
          print('$hostport: unknown packet number: $packetId, len $packetLen');
        }
        break;
    }
  }

  void handleMSG_KEXDH_INIT(int packetId, Uint8List packet) {
    if (packetId == MSG_KEX_ECDH_INIT.ID &&
        KEX.x25519DiffieHellman(kexMethod)) {
      handleX25519MSG_KEX_ECDH_INIT(MSG_KEX_ECDH_INIT()..deserialize(packetS));
    } else if (packetId == MSG_KEX_ECDH_INIT.ID &&
        KEX.ellipticCurveDiffieHellman(kexMethod)) {
      handleEcDhMSG_KEX_ECDH_INIT(MSG_KEX_ECDH_INIT()..deserialize(packetS));
    } else if ((packetId == MSG_KEXDH_INIT.ID &&
            KEX.diffieHellman(kexMethod)) ||
        (packetId == MSG_KEX_DH_GEX_INIT.ID &&
            KEX.diffieHellmanGroupExchange(kexMethod))) {
      handleDhMSG_KEXDH_INIT(packetId, MSG_KEXDH_INIT()..deserialize(packetS));
    } else {
      throw FormatException('unknown kex: $kexMethod');
    }
  }

  void handleX25519MSG_KEX_ECDH_INIT(MSG_KEX_ECDH_INIT msg) {
    initializeDiffieHellman(kexMethod, random);
    K = x25519dh.computeSecret(msg.qC);
    Uint8List kS = identity.getRawPublicKey(hostkeyType);
    updateExchangeHash(kS);
    writeClearOrEncrypted(MSG_KEX_ECDH_REPLY(x25519dh.myPubKey, kS,
        identity.signMessage(hostkeyType, exH, getSecureRandom())));
    sendNewKeys();
  }

  void handleEcDhMSG_KEX_ECDH_INIT(MSG_KEX_ECDH_INIT msg) {
    initializeDiffieHellman(kexMethod, random);
    K = ecdh.computeSecret(msg.qC);
    Uint8List kS = identity.getRawPublicKey(hostkeyType);
    updateExchangeHash(kS);
    writeClearOrEncrypted(MSG_KEX_ECDH_REPLY(ecdh.cText, kS,
        identity.signMessage(hostkeyType, exH, getSecureRandom())));
    sendNewKeys();
  }

  void handleDhMSG_KEXDH_INIT(int packetId, MSG_KEXDH_INIT msg) {
    if (packetId != MSG_KEX_DH_GEX_INIT.ID) {
      initializeDiffieHellman(kexMethod, random);
    }
    K = dh.computeSecret(msg.e);
    Uint8List kS = identity.getRawPublicKey(hostkeyType);
    updateExchangeHash(kS);
    Uint8List hSig = identity.signMessage(hostkeyType, exH, getSecureRandom());
    writeClearOrEncrypted(packetId == MSG_KEX_DH_GEX_INIT.ID
        ? MSG_KEX_DH_GEX_REPLY(dh.e, kS, hSig)
        : MSG_KEXDH_REPLY(dh.e, kS, hSig));
    sendNewKeys();
  }

  void handleMSG_KEX_DH_GEX_REQUEST(MSG_KEX_DH_GEX_REQUEST msg) {
    MapEntry<BigInt, BigInt> group =
        gexRequest == null ? null : gexRequest(msg);
    if (group == null) {
      DiffieHellman group14 = DiffieHellman.group14();
      group = MapEntry<BigInt, BigInt>(group14.p, group14.g);
    }
    initializeDiffieHellman(kexMethod, random);
    initializeDiffieHellmanGroup(group.key, group.value, random);
    writeClearOrEncrypted(MSG_KEX_DH_GEX_GROUP(group.key, group.value));
  }

  void handleMSG_SERVICE_REQUEST(MSG_SERVICE_REQUEST msg) {
    switch (msg.serviceName) {
      case 'ssh-userauth':
        writeCipher(MSG_SERVICE_ACCEPT(msg.serviceName));
        break;

      default:
        throw FormatException('service name ${msg.serviceName}');
    }
  }

  void handleMSG_USERAUTH_REQUEST(MSG_USERAUTH_REQUEST msg) {
    if (tracePrint != null) {
      tracePrint('$hostport: MSG_USERAUTH_REQUEST: $msg');
    }

    if (userAuthRequest != null && userAuthRequest(msg)) {
      writeCipher(MSG_USERAUTH_SUCCESS());
    } else {
      writeCipher(MSG_USERAUTH_FAILURE());
    }
  }

  void handleMSG_CHANNEL_OPEN(MSG_CHANNEL_OPEN msg, SerializableInput packetS) {
    if (tracePrint != null) {
      tracePrint('$hostport: MSG_CHANNEL_OPEN type=${msg.channelType}');
    }
    if (msg.channelType == 'session') {
      if (sessionChannel != null) {
        throw FormatException('already started session');
      }
      sessionChannel = acceptChannel(msg);
      writeCipher(MSG_CHANNEL_OPEN_CONFIRMATION(sessionChannel.remoteId,
          sessionChannel.localId, sessionChannel.windowS, maxPacketSize));
    } else if (msg.channelType == 'direct-tcpip' && directTcpRequest != null) {
      MSG_CHANNEL_OPEN_TCPIP tcpip = MSG_CHANNEL_OPEN_TCPIP()
        ..deserialize(packetS);
      Channel tcpipChannel = acceptChannel(msg);
      directTcpRequest(tcpipChannel, tcpip.srcHost, tcpip.srcPort,
              tcpip.dstHost, tcpip.dstPort)
          .then((String error) {
        if (error == null) {
          writeCipher(MSG_CHANNEL_OPEN_CONFIRMATION(tcpipChannel.remoteId,
              tcpipChannel.localId, tcpipChannel.windowS, maxPacketSize));
        } else {
          writeCipher(MSG_CHANNEL_OPEN_FAILURE(msg.senderChannel, 0, '', ''));
        }
      });
    } else {
      if (print != null) {
        print('unknown channel open ${msg.channelType}');
      }
      writeCipher(MSG_CHANNEL_OPEN_FAILURE(msg.senderChannel, 0, '', ''));
    }
  }

  void handleMSG_CHANNEL_REQUEST(MSG_CHANNEL_REQUEST msg) {
    if (tracePrint != null) {
      tracePrint(
          '$hostport: MSG_CHANNEL_REQUEST ${msg.requestType} wantReply=${msg.wantReply}');
    }
    Channel chan = channels[msg.recipientChannel];
    if (chan == sessionChannel &&
        sessionChannelRequest != null &&
        sessionChannelRequest(this, msg.requestType)) {
      if (msg.wantReply) {
        writeCipher(MSG_CHANNEL_SUCCESS(chan.remoteId));
      }
    } else {
      if (msg.wantReply) {
        writeCipher(MSG_CHANNEL_FAILURE(chan != null ? chan.remoteId : 0));
      }
    }
  }

  @override
  void handleChannelOpenConfirmation(Channel channel) {
    if (channel.connected != null) {
      channel.connected();
    }
  }

  @override
  void handleChannelData(Channel channel, Uint8List data) {
    if (channel == sessionChannel) {
      response(this, utf8.decode(data));
    } else if (channel.cb != null) {
      channel.cb(channel, data);
    }
  }

  @override
  void handleChannelClose(Channel channel, [String description]) {
    if (channel == sessionChannel) {
      sessionChannel = null;
    } else if (channel.cb != null) {
      channel.opened = false;
      channel.cb(channel, Uint8List(0));
    }
  }

  @override
  void sendChannelData(Uint8List b) {
    if (sessionChannel != null) {
      sendToChannel(sessionChannel, b);
    }
  }

  Channel openAgentChannel(ChannelCallback cb,
      {VoidCallback connected, StringCallback error}) {
    if (debugPrint != null) debugPrint('openAgentChannel');
    if (socket == null || state <= SSHTransportState.FIRST_NEWKEYS) return null;
    Channel chan = channels[nextChannelId] = Channel(
        localId: nextChannelId++,
        windowS: initialWindowSize,
        cb: cb,
        error: error,
        connected: connected)
      ..agentChannel = true;
    nextChannelId++;
    writeCipher(MSG_CHANNEL_OPEN(
        'auth-agent@openssh.com', chan.localId, chan.windowS, maxPacketSize));
    return chan;
  }
}
