// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import "package:pointycastle/api.dart";
import "package:pointycastle/digests/sha256.dart";
import 'package:pointycastle/macs/hmac.dart';
import 'package:validators/sanitizers.dart';

import 'package:dartssh/protocol.dart';
import 'package:dartssh/serializable.dart';
import 'package:dartssh/socket.dart';
import 'package:dartssh/socket_html.dart'
    if (dart.library.io) 'package:dartssh/socket_io.dart';
import 'package:dartssh/ssh.dart';

typedef VoidCallback = void Function();
typedef StringCallback = void Function(String);
typedef FingerprintCallback = bool Function(int, Uint8List);

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
  FingerprintCallback hostFingerprint;

  /*LoadIdentityCB loadIdentityCb;
  LoadPasswordCB loadPasswordCb;
  RemoteForwardCB remoteForwardCb;
  sharedPtr<Identity> identity;*/

  String verC = 'SSH-2.0-dartssh_1.0', verS, login, pw;
  Uint8List kexInitC,
      kexInitS,
      decryptBuf,
      hText,
      sessionId,
      integrityC2s,
      integrityS2c;

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
  int cipherIdC2s = 0, cipherIdS2c = 0, macIdC2s = 0, macIdS2c = 0;

  SocketInterface socket;
  Random random;
  QueueBuffer readBuffer = QueueBuffer(Uint8List(0));
  SerializableInput packetS;

  DiffieHellman dh = DiffieHellman();
  EllipticCurveDiffieHellman ecdh = EllipticCurveDiffieHellman();
  X25519DiffieHellman x25519dh = X25519DiffieHellman();
  Digest kexHash;
  BlockCipher encrypt, decrypt;
  HMac macAlgoC2s, macAlgoS2c;
  BigInt K;

  /*unorderedMap<int, SSHClient::Channel> channels;
  SSHClient::Channel *sessionChannel=0;
  BigNumContext ctx;
  ECDef curveId;*/
  int nextChannelId = 1, compressIdC2s, compressIdS2c;
  int kexMethod = 0, hostkeyType = 0, macPrefixC2s = 0, macPrefixS2c = 0;
  int initialWindowSize = 1048576,
      maxPacketSize = 32768,
      termWidth = 80,
      termHeight = 25;
  ZLibDecoder zreader;
  ZLibEncoder zwriter;
  //unorderedMap<int, const SSHClient::Params::Forward*> forwardRemote;

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
            macPref, macPref, compressPref, compressPref, '', '', guess)
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
        if (readBuffer.data.length < BinaryPacket.headerSize ||
            (encrypted && readBuffer.data.length < decryptBlockSize)) {
          return;
        }
        //if (encrypted) decryptBuf = ReadCipher(c, StringPiece(c->rb.begin(), decryptBlockSize));
        BinaryPacket binaryPacket =
            BinaryPacket(encrypted ? decryptBuf : readBuffer.data);
        packetLen = 4 + binaryPacket.length + packetMacLen;
        padding = binaryPacket.padding;
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
            packet.offsetInBytes + BinaryPacket.headerSize,
            packetLen - BinaryPacket.headerSize - packetMacLen - padding));
      }

      handlePacket(packet);
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

  void handlePacket(Uint8List packet) {
    packetId = packetS.getUint8();
    switch (packetId) {
      case MSG_KEXINIT.ID:
        state = state == SSHClientState.FIRST_KEXINIT
            ? SSHClientState.FIRST_KEXREPLY
            : SSHClientState.KEXREPLY;
        handleMSG_KEXINIT(MSG_KEXINIT()..deserialize(packetS), packet);
        break;

      case MSG_KEXDH_REPLY.ID:
      case MSG_KEX_DH_GEX_REPLY.ID:
        handleMSG_KEXDH_REPLY(packetId, packet);
        break;

      case MSG_NEWKEYS.ID:
        handleMSG_NEWKEYS();
        break;

      default:
        print('$hostport: unknown packet number: $packetId, len $packetLen');
        break;
    }
  }

  void handleMSG_KEXINIT(MSG_KEXINIT msg, Uint8List packet) {
    tracePrint('$hostport: MSG_KEXINIT $msg');

    guessedS = msg.firstKexPacketFollows;
    kexInitS = packet.sublist(0, packetLen - packetMacLen);

    if (0 == (kexMethod = KEX.preferenceIntersect(msg.kexAlgorithms))) {
      throw FormatException('$hostport: negotiate kex');
    } else if (0 ==
        (hostkeyType = Key.preferenceIntersect(msg.serverHostKeyAlgorithms))) {
      throw FormatException('$hostport: negotiate hostkey');
    } else if (0 ==
        (cipherIdC2s = Cipher.preferenceIntersect(
            msg.encryptionAlgorithmsClientToServer))) {
      throw FormatException('$hostport: negotiate c2s cipher');
    } else if (0 ==
        (cipherIdS2c = Cipher.preferenceIntersect(
            msg.encryptionAlgorithmsServerToClient))) {
      throw FormatException('$hostport: negotiate s2c cipher');
    } else if (0 ==
        (macIdC2s = MAC.preferenceIntersect(msg.macAlgorithmsClientToServer))) {
      throw FormatException('$hostport: negotiate c2s mac');
    } else if (0 ==
        (macIdS2c = MAC.preferenceIntersect(msg.macAlgorithmsServerToClient))) {
      throw FormatException('$hostport: negotiate s2c mac');
    } else if (0 ==
        (compressIdC2s = Compression.preferenceIntersect(
            msg.compressionAlgorithmsClientToServer, compress ? 0 : 1))) {
      throw FormatException('$hostport: negotiate c2s compression');
    } else if (0 ==
        (compressIdS2c = Compression.preferenceIntersect(
            msg.compressionAlgorithmsServerToClient, compress ? 0 : 1))) {
      throw FormatException('$hostport: negotiate s2c compression');
    }

    guessedRightS = kexMethod == KEX.id(msg.kexAlgorithms.split(',')[0]) &&
        hostkeyType == Key.id(msg.serverHostKeyAlgorithms.split(',')[0]);
    guessedRightC = kexMethod == 1 && hostkeyType == 1;
    encryptBlockSize = Cipher.blockSize(cipherIdC2s);
    decryptBlockSize = Cipher.blockSize(cipherIdS2c);
    macAlgoC2s = MAC.mac(macIdC2s);
    macPrefixC2s = MAC.prefixBytes(macIdC2s);
    macAlgoS2c = MAC.mac(macIdS2c);
    macPrefixS2c = MAC.prefixBytes(macIdS2c);

    print('$hostport: ssh negotiated { kex=${KEX.name(kexMethod)}, hostkey=${Key.name(hostkeyType)}' +
        (cipherIdC2s == cipherIdS2c
            ? ', cipher=${Cipher.name(cipherIdC2s)}'
            : ', cipherC2s=${Cipher.name(cipherIdC2s)}, cipherS2c=${Cipher.name(cipherIdS2c)}') +
        (macIdC2s == macIdS2c
            ? ', mac=${MAC.name(macIdC2s)}'
            : ', macC2s=${MAC.name(macIdC2s)},  macS2c=${MAC.name(macIdS2c)}') +
        (compressIdC2s == compressIdS2c
            ? ', compress=${Compression.name(compressIdC2s)}'
            : ', compressC2s=${Compression.name(compressIdC2s)}, compressS2c=${Compression.name(compressIdS2c)}') +
        " }");
    tracePrint(
        '$hostport: blockSize=$encryptBlockSize,$decryptBlockSize, macLen=$macLenC,$macLenS');

    if (KEX.x25519DiffieHellman(kexMethod)) {
      kexHash = SHA256Digest();
      x25519dh.GeneratePair(random);
      writeClearOrEncrypted(MSG_KEX_ECDH_INIT(x25519dh.myPubKey));
    }
  }

  void handleMSG_KEXDH_REPLY(int packetId, Uint8List packet) {
    if (state != SSHClientState.FIRST_KEXREPLY &&
        state != SSHClientState.KEXREPLY) {
      throw FormatException('$hostport: unexpected state $state');
    }
    if (guessedS && !guessedRightS) {
      guessedS = false;
      print('$hostport: server guessed wrong, ignoring packet');
      return;
    }

    Uint8List fingerprint;
    if (packetId == MSG_KEX_ECDH_REPLY.ID &&
        KEX.x25519DiffieHellman(kexMethod)) {
      fingerprint = handleX25519MSG_KEX_ECDH_REPLY(
              MSG_KEX_ECDH_REPLY()..deserialize(packetS)) ??
          fingerprint;
      // fall thru
    } else {
      throw FormatException('$hostport: unsupported $packetId, $kexMethod');
    }

    writeClearOrEncrypted(MSG_NEWKEYS());
    if (state == SSHClientState.FIRST_KEXREPLY) {
      state = SSHClientState.FIRST_NEWKEYS;
      if (hostFingerprint != null) {
        acceptedHostkey = hostFingerprint(hostkeyType, fingerprint);
      } else {
        acceptedHostkey = true;
      }
    } else {
      state = SSHClientState.NEWKEYS;
    }
  }

  Uint8List handleX25519MSG_KEX_ECDH_REPLY(MSG_KEX_ECDH_REPLY msg) {
    Uint8List fingerprint;
    tracePrint('$hostport: MSG_KEX_ECDH_REPLY for X25519DH');
    if (!acceptedHostkey) fingerprint = msg.kS;

    x25519dh.remotePubKey = msg.qS;
    K = x25519dh.computeSecret();
    if (!computeExchangeHashAndVerifyHostKey(msg.kS, msg.hSig)) {
      throw FormatException('$hostport: verify hostkey failed');
    }

    return fingerprint;
  }

  void handleMSG_NEWKEYS() {
    if (state != SSHClientState.FIRST_NEWKEYS &&
        state != SSHClientState.NEWKEYS) {
      throw FormatException('$hostport: unexpected state $state');
    }
    if (tracePrint != null) {
      tracePrint('$hostport: MSG_NEWKEYS');
    }
    int keyLenC = Cipher.keySize(cipherIdC2s),
        keyLenS = Cipher.keySize(cipherIdS2c);
    encrypt = initCipher(
        cipherIdC2s,
        deriveKey(kexHash, sessionId, hText, K, 'A'.codeUnits[0], 24),
        deriveKey(kexHash, sessionId, hText, K, 'C'.codeUnits[0], keyLenC),
        true);
    decrypt = initCipher(
        cipherIdS2c,
        deriveKey(kexHash, sessionId, hText, K, 'B'.codeUnits[0], 24),
        deriveKey(kexHash, sessionId, hText, K, 'D'.codeUnits[0], keyLenS),
        false);
    if ((macLenC = MAC.hashSize(macIdC2s)) <= 0) {
      throw FormatException('$hostport: invalid maclen $encryptBlockSize');
    } else if ((macLenS = MAC.hashSize(macIdS2c)) <= 0) {
      throw FormatException('$hostport: invalid maclen $encryptBlockSize');
    }
    integrityC2s =
        deriveKey(kexHash, sessionId, hText, K, 'E'.codeUnits[0], macLenC);
    integrityS2c =
        deriveKey(kexHash, sessionId, hText, K, 'F'.codeUnits[0], macLenS);
    state = SSHClientState.NEWKEYS;
    writeCipher(MSG_SERVICE_REQUEST('ssh-userauth'));
  }

  bool computeExchangeHashAndVerifyHostKey(Uint8List kS, Uint8List hSig) {
    hText = computeExchangeHash(kexMethod, kexHash, verC, verS, kexInitC,
        kexInitS, kS, K, dh, ecdh, x25519dh);
    if (state == SSHClientState.FIRST_KEXREPLY) sessionId = hText;
    if (tracePrint != null) {
      tracePrint('$hostport: H = "${hex.encode(hText)}"');
    }
    return verifyHostKey(hText, hostkeyType, kS, hSig);
  }

  BlockCipher initCipher(int cipherId, Uint8List IV, Uint8List key, bool dir) {
    BlockCipher cipher = Cipher.cipher(cipherId);
    if (tracePrint != null) {
      tracePrint('$hostport: ' +
          (dir ? 'C->S' : 'S->C') +
          ' IV  = "${hex.encode(IV)}"');
      tracePrint('$hostport: ' +
          (dir ? 'C->S' : 'S->C') +
          ' key = "${hex.encode(key)}"');
    }
    cipher.init(dir, ParametersWithIV(KeyParameter(key), Uint8List.view(IV.buffer, 0, cipher.blockSize)));
    return cipher;
  }

  void writeCipher(SSHMessage msg) {
    sequenceNumberC2s++;
    Uint8List m = msg.toBytes(zwriter, random, encryptBlockSize), encM = Uint8List(m.length);
    assert(m.length % encryptBlockSize == 0);
    for (int offset = 0; offset < m.length; offset += encryptBlockSize) {
      encrypt.processBlock(m, offset, encM, offset);
    }
    Uint8List mac = computeMAC(MAC.mac(macIdC2s), macLenC, m,
        sequenceNumberC2s - 1, integrityC2s, macPrefixC2s);
    socket.sendRaw(Uint8List.fromList(encM + mac));
  }

  void writeClearOrEncrypted(SSHMessage m) {
    if (state > SSHClientState.FIRST_NEWKEYS) return writeCipher(m);
    sequenceNumberC2s++;
    socket.sendRaw(m.toBytes(null, random, encryptBlockSize));
  }
}
