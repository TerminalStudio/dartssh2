// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:math';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:validators/sanitizers.dart';

import 'package:dartssh/protocol.dart';
import 'package:dartssh/serializable.dart';
import 'package:dartssh/socket.dart';
import 'package:dartssh/socket_html.dart'
    if (dart.library.io) 'package:dartssh/socket_io.dart';
import 'package:dartssh/ssh.dart';

typedef VoidCallback = void Function();
typedef StringCallback = void Function(String);

class Forward {
  int port, targetPort;
  String targetHost;
}

class SSHClientState {
  static const int INIT = 0,
      FIRST_KEXINIT = 1,
      FIRST_KEXREPLY = 2,
      FIRST_NEWKEYS = 3,
      KEXINIT = 4,
      KEXREPLY = 5,
      NEWKEYS = 6;
}

class SSHClient {
  String hostport, user, termvar, startupCommand;
  bool compress, agentForwarding, closeOnDisconnect, backgroundServices;
  List<Forward> forwardLocal, forwardRemote;
  StringCallback response, debugPrint, tracePrint;
  VoidCallback success;
  /*FingerprintCB hostFingerprintCb;
  LoadIdentityCB loadIdentityCb;
  LoadPasswordCB loadPasswordCb;
  RemoteForwardCB remoteForwardCb;
  sharedPtr<Identity> identity;*/

  String verC = 'SSH-2.0-dartssh_1.0', verS;
  Uint8List kexInitC, kexInitS, decryptBuf;
  String hText, sessionId, integrityC2s, integrityS2c, login, pw;
  num serverVersion = 0;
  int state = 0,
      packetLen = 0,
      packetMacLen = 0,
      macLenC = 0,
      macLenS = 0,
      encryptBlockSize = 0,
      decryptBlockSize = 0;
  int sequenceNumberC2s = 0,
      sequenceNumberS2c = 0,
      loginPrompts = 0,
      passwordPrompts = 0,
      userauthFail = 0;
  bool guessedC = false,
      guessedS = false,
      guessedRightC = false,
      guessedRightS = false,
      acceptedHostkey = false,
      loadedPw = false,
      wrotePw = false;
  int padding = 0, packetId = 0;

  SocketInterface socket;
  Random random;
  QueueBuffer readBuffer = QueueBuffer(Uint8List(0));
  SerializableInput packetS;

  /*unorderedMap<int, SSHClient::Channel> channels;
  SSHClient::Channel *sessionChannel=0;
  BigNumContext ctx;
  BigNum K;
  Crypto::DiffieHellman dh;
  Crypto::EllipticCurveDiffieHellman ecdh;
  Crypto::X25519DiffieHellman x25519dh;
  Crypto::DigestAlgo kexHash;
  Crypto::Cipher encrypt, decrypt;
  Crypto::CipherAlgo cipherAlgoC2s, cipherAlgoS2c; 
  Crypto::MACAlgo macAlgoC2s, macAlgoS2c;
  ECDef curveId;*/
  int nextChannelId = 1, compressIdC2s, compressIdS2c;
  int kexMethod = 0, hostkeyType = 0, macPrefixC2s = 0, macPrefixS2c = 0;
  int initialWindowSize = 1048576,
      maxPacketSize = 32768,
      termWidth = 80,
      termHeight = 25;
  //unorderedMap<int, const SSHClient::Params::Forward*> forwardRemote;
  //uniquePtr<ZLibReader> zreader;
  //uniquePtr<ZLibWriter> zwriter;

  SSHClient(
      {this.hostport,
      this.user,
      this.termvar,
      this.startupCommand,
      this.compress = false,
      this.agentForwarding = false,
      this.closeOnDisconnect,
      this.backgroundServices,
      this.forwardLocal,
      this.forwardRemote,
      this.response,
      this.success,
      this.debugPrint,
      this.tracePrint,
      this.socket,
      this.random}) {
    socket ??= SocketImpl();
    random ??= Random.secure();
    if (debugPrint != null) {
      debugPrint('Connecting to $hostport');
    }
    socket.connect(
        hostport, onConnected, (error) => disconnect('connect error'));
  }

  void disconnect(String reason) {
    socket.close();
    if (debugPrint != null) debugPrint('disconnected: ' + reason);
  }

  void onConnected(dynamic x) {
    socket.handleError((error) => disconnect('socket error'));
    socket.handleDone((v) => disconnect('socket done'));
    socket.listen(handleRead);
    handleConnected();
  }

  void handleConnected() {
    if (debugPrint != null) debugPrint('handleConnected');
    if (state != SSHClientState.INIT) throw FormatException('$state');
    socket.send(verC + '\r\n');
    sendKeyExchangeInit(false);
  }

  void sendKeyExchangeInit(bool guess) {
    String keyPref = Key.preferenceCsv(),
        kexPref = KEX.preferenceCsv(),
        cipherPref = Cipher.preferenceCsv(),
        macPref = MAC.preferenceCsv(),
        compressPref = Compression.preferenceCsv(compress ? 0 : 1);

    sequenceNumberC2s++;
    kexInitC = MSG_KEXINIT
        .create(randBytes(random, 16), kexPref, keyPref, cipherPref, cipherPref,
            macPref, macPref, compressPref, compressPref, '', '', guess ? 1 : 0)
        .toBytes(null, random, 8);

    if (debugPrint != null) {
      debugPrint(
          '$hostport wrote KEXINIT_C { kex=$kexPref key=$keyPref, cipher=$cipherPref, mac=$macPref, compress=$compressPref }');
    }
    socket.sendRaw(kexInitC);
  }

  void handleRead(Uint8List dataChunk) {
    readBuffer.add(dataChunk);

    if (state == SSHClientState.INIT) {
      handleInitialState();
      if (state == SSHClientState.INIT) return;
    }

    // SSHClient::Channel *chan;
    while (true) {
      bool encrypted = state > SSHClientState.FIRST_NEWKEYS;

      if (packetLen == 0) {
        packetMacLen =
            macLenS != 0 ? (macPrefixS2c != 0 ? macPrefixS2c : macLenS) : 0;
        if (readBuffer.data.length < binaryPacketHeaderSize ||
            (encrypted && readBuffer.data.length < decryptBlockSize)) {
          return;
        }
        //if (encrypted) decryptBuf = ReadCipher(c, StringPiece(c->rb.begin(), decryptBlockSize));
        SerializableInput packet =
            SerializableInput(encrypted ? decryptBuf : readBuffer.data);
        packetLen = 4 + packet.getUint32() + packetMacLen;
        padding = packet.getUint8();
      }
      if (readBuffer.data.length < packetLen) return;
      /*if (encrypted) decryptBuf +=
				ReadCipher(c, StringPiece(c->rb.begin() + decryptBlockSize, packetLen - decryptBlockSize - packetMacLen));*/

      sequenceNumberS2c++;
      /*if (encrypted && packetMacLen) {
				string mac = SSH::MAC(macAlgoS2c, MACLenS, StringPiece(decryptBuf.data(), packetLen - packetMacLen),
															sequenceNumberS2c-1, integrityS2c, macPrefixS2c);
				if (mac != string(c->rb.begin() + packetLen - packetMacLen, packetMacLen))
					return ERRORv(-1, c->Name(), ": verify MAC failed");
			}*/

      Uint8List packet = encrypted ? decryptBuf : readBuffer.data;
      /*if (zreader) {
        zreader->out.clear();
        if (!zreader->Add(StringPiece(packet    + SSH::BinaryPacketHeaderSize,
                                      packetLen - SSH::BinaryPacketHeaderSize - packetMacLen - padding),
                          true)) ERRORv(-1, c->Name(), ": decompress failed");
        packetS = Serializable::ConstStream((packet = zreader->out.data()), zreader->out.size());
      } else*/
      if (true) {
        packetS = SerializableInput(Uint8List.view(
            packet.buffer,
            packet.offsetInBytes + binaryPacketHeaderSize,
            packetLen - binaryPacketHeaderSize - packetMacLen - padding));
      }

      handlePacket();
      readBuffer.flush(packetLen);
      packetLen = 0;
    }
  }

  /// Protocol Version Exchange
  void handleInitialState() {
    int processed = 0, newlineIndex;
    while ((newlineIndex =
            readBuffer.data.indexOf('\n'.codeUnits[0], processed)) !=
        -1) {
      String line = String.fromCharCodes(Uint8List.view(
              readBuffer.data.buffer,
              readBuffer.data.offsetInBytes + processed,
              newlineIndex - processed))
          .trim();
      if (tracePrint != null) tracePrint('$hostport: SSH_INIT: $line');
      processed = newlineIndex + 1;
      if (line.startsWith('SSH-')) {
        verS = line;
        serverVersion = toFloat(line.substring(4));
        state++;
        break;
      }
    }
    readBuffer.flush(processed);
  }

  void handlePacket() {
    int v;
    packetId = packetS.getUint8();
    switch (packetId) {
      case MSG_KEXINIT.ID:
        state = state == SSHClientState.FIRST_KEXINIT
            ? SSHClientState.FIRST_KEXREPLY
            : SSHClientState.KEXREPLY;
        MSG_KEXINIT msg = MSG_KEXINIT();
        msg.deserialize(packetS);
        assert(packetS.done);
        tracePrint('$hostport: MSG_KEXINIT $msg');
        break;

      default:
        print('$hostport: unknown packet number: $packetId, len $packetLen');
        break;
    }
  }
}
