// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:math';
import 'dart:typed_data';

import "package:pointycastle/api.dart";

import 'package:dartssh/identity.dart';
import 'package:dartssh/socket.dart';
import 'package:dartssh/ssh.dart';
import 'package:dartssh/protocol.dart';
import 'package:dartssh/transport.dart';

class SSHServer extends SSHTransport {
  Identity hostkey;
  SSHServer(this.hostkey,
      {String hostport,
      bool compress = false,
      List<Forward> forwardLocal,
      List<Forward> forwardRemote,
      VoidCallback disconnected,
      StringCallback response,
      StringCallback print,
      StringCallback debugPrint,
      StringCallback tracePrint,
      SocketInterface socket,
      Random random,
      SecureRandom secureRandom})
      : super(true,
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
    onConnected(socket);
  }

  /// Does nothing.  The client initializes Diffie Hellman.
  @override
  void sendDiffileHellmanInit() {}

  @override
  void handlePacket(Uint8List packet) {
    packetId = packetS.getUint8();
    switch (packetId) {
      case MSG_KEXINIT.ID:
        state = state == SSHClientState.FIRST_KEXINIT
            ? SSHClientState.FIRST_KEXREPLY
            : SSHClientState.KEXREPLY;
        handleMSG_KEXINIT(MSG_KEXINIT()..deserialize(packetS), packet);
        break;

      case MSG_KEXDH_INIT.ID:
        handleMSG_KEXDH_INIT(packetId, packet);
        break;

      case MSG_NEWKEYS.ID:
        handleMSG_NEWKEYS();
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
    } else if (packetId == MSG_KEXDH_INIT.ID && true) {
      /**/
    } else {
      /**/
    }
  }

  void handleX25519MSG_KEX_ECDH_INIT(MSG_KEX_ECDH_INIT msg) {
    initializeDiffieHellman(kexMethod, random);
    K = x25519dh.computeSecret(msg.qC);
    Uint8List kS = hostkey.getRawPublicKey(hostkeyType);
    computeTheExchangeHash(kS);
    writeClearOrEncrypted(MSG_KEX_ECDH_REPLY(x25519dh.myPubKey, kS,
        hostkey.signMessage(hostkeyType, exH, getSecureRandom())));
    writeClearOrEncrypted(MSG_NEWKEYS());
    if (state == SSHClientState.FIRST_KEXREPLY) {
      state = SSHClientState.FIRST_NEWKEYS;
    } else {
      state = SSHClientState.NEWKEYS;
    }
  }

  void handleEcDhMSG_KEX_ECDH_INIT(MSG_KEX_ECDH_INIT msg) {
    initializeDiffieHellman(kexMethod, random);
    K = ecdh.computeSecret(msg.qC);
    Uint8List kS = hostkey.getRawPublicKey(hostkeyType);
    computeTheExchangeHash(kS);
    writeClearOrEncrypted(MSG_KEX_ECDH_REPLY(ecdh.cText, kS,
        hostkey.signMessage(hostkeyType, exH, getSecureRandom())));
  }
}
