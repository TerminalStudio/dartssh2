// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:math';
import 'dart:collection';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import "package:pointycastle/api.dart";
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/random/fortuna_random.dart';
import 'package:validators/sanitizers.dart';

import 'package:dartssh/identity.dart';
import 'package:dartssh/kex.dart';
import 'package:dartssh/protocol.dart';
import 'package:dartssh/serializable.dart';
import 'package:dartssh/socket.dart';
import 'package:dartssh/ssh.dart';

typedef VoidCallback = void Function();
typedef StringCallback = void Function(String);
typedef StringFunction = String Function();
typedef Uint8ListFunction = Uint8List Function();
typedef IdentityFunction = Identity Function();
typedef FingerprintCallback = bool Function(int, Uint8List);
typedef ChannelCallback = void Function(Channel, Uint8List);
typedef RemoteForwardCallback = void Function(
    Channel, String, int, String, int);

class Forward {
  int port, targetPort;
  String targetHost;
}

class Channel {
  int localId, remoteId, windowC = 0, windowS = 0;
  bool opened = true, agentChannel = false, sentEof = false, sentClose = false;
  QueueBuffer buf = QueueBuffer(Uint8List(0));
  ChannelCallback cb;
  Channel([this.localId = 0, this.remoteId = 0]);
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

/// https://tools.ietf.org/html/rfc4253
abstract class SSHTransport with SSHDiffieHellman {
  String hostport;
  bool compress;
  Random random;
  SecureRandom secureRandom;
  VoidCallback disconnected;
  StringCallback response, print, debugPrint, tracePrint;
  List<Forward> forwardLocal, forwardRemote;
  RemoteForwardCallback remoteForward;

  String verC = 'SSH-2.0-dartssh_1.0', verS;

  num serverVersion = 0;

  int state = 0,
      padding = 0,
      packetId = 0,
      packetLen = 0,
      packetMacLen = 0,
      hostkeyType = 0,
      kexMethod = 0,
      macPrefixC2s = 0,
      macPrefixS2c = 0,
      macLenC = 0,
      macLenS = 0,
      macIdC2s = 0,
      macIdS2c = 0,
      cipherIdC2s = 0,
      cipherIdS2c = 0,
      compressIdC2s = 0,
      compressIdS2c = 0,
      encryptBlockSize = 0,
      decryptBlockSize = 0,
      sequenceNumberC2s = 0,
      sequenceNumberS2c = 0,
      nextChannelId = 1;

  bool guessedC = false,
      guessedS = false,
      guessedRightC = false,
      guessedRightS = false;

  SocketInterface socket;
  QueueBuffer readBuffer = QueueBuffer(Uint8List(0));
  SerializableInput packetS;
  Uint8List kexInitC,
      kexInitS,
      decryptBuf,
      exH,
      sessionId,
      integrityC2s,
      integrityS2c;

  BigInt K;
  BlockCipher encrypt, decrypt;
  HMac macAlgoC2s, macAlgoS2c;

  int initialWindowSize = 1048576, maxPacketSize = 32768;
  bool server;
  bool get client => !server;

  dynamic zreader;
  dynamic zwriter;
  HashMap<int, Forward> forwardingRemote;

  HashMap<int, Channel> channels = HashMap<int, Channel>();

  SSHTransport(this.server,
      {this.hostport,
      this.compress,
      this.forwardLocal,
      this.forwardRemote,
      this.disconnected,
      this.response,
      this.print,
      this.debugPrint,
      this.tracePrint,
      this.socket,
      this.random,
      this.secureRandom}) {
    random ??= Random.secure();
  }

  void sendDiffileHellmanInit();
  void handlePacket(Uint8List packet);

  SecureRandom getSecureRandom() {
    if (secureRandom != null) return secureRandom;
    return (secureRandom = FortunaRandom())
      ..seed(KeyParameter(randBytes(random, 32)));
  }

  /// If anything goes wrong, disconnect with [reason].
  void disconnect(String reason) {
    socket.close();
    if (debugPrint != null) debugPrint('disconnected: ' + reason);
    if (disconnected != null) disconnected();
  }

  /// Callback supplied to [socket.connect].
  void onConnected(dynamic x) {
    socket.handleError((error) => disconnect('socket error: $error'));
    socket.handleDone((v) => disconnect('socket done'));
    socket.listen(handleRead);
    handleConnected();
  }

  /// When the connection has been established, both sides MUST send an identification string.
  /// https://tools.ietf.org/html/rfc4253#section-4.2
  void handleConnected() {
    if (debugPrint != null) debugPrint('handleConnected');
    if (state != SSHClientState.INIT) throw FormatException('$state');
    socket.send(verC + '\r\n');
    if (client) sendKeyExchangeInit(false);
  }

  /// Key exchange begins by each side sending SSH_MSG_KEXINIT.
  void sendKeyExchangeInit(bool guess) {
    String keyPref = Key.preferenceCsv(),
        kexPref = KEX.preferenceCsv(),
        cipherPref = Cipher.preferenceCsv(),
        macPref = MAC.preferenceCsv(),
        compressPref = Compression.preferenceCsv(compress ? 0 : 1);

    sequenceNumberC2s++;
    Uint8List kexInit = MSG_KEXINIT
        .create(randBytes(random, 16), kexPref, keyPref, cipherPref, cipherPref,
            macPref, macPref, compressPref, compressPref, '', '', guess)
        .toBytes(null, random, 8);
    if (client) {
      kexInitC = kexInit;
    } else {
      kexInitS = kexInit;
    }

    if (debugPrint != null) {
      debugPrint(
          '$hostport wrote KEXINIT { kex=$kexPref key=$keyPref, cipher=$cipherPref, mac=$macPref, compress=$compressPref }');
    }
    socket.sendRaw(kexInit);
  }

  /// Callback supplied to [socket.listen].
  void handleRead(Uint8List dataChunk) {
    readBuffer.add(dataChunk);

    if (state == SSHClientState.INIT) {
      handleInitialState();
      if (state == SSHClientState.INIT) return;
    }

    while (true) {
      bool encrypted = state > SSHClientState.FIRST_NEWKEYS;

      if (packetLen == 0) {
        packetMacLen =
            macLenS != 0 ? (macPrefixS2c != 0 ? macPrefixS2c : macLenS) : 0;
        if (readBuffer.data.length < BinaryPacket.headerSize ||
            (encrypted && readBuffer.data.length < decryptBlockSize)) {
          return;
        }
        if (encrypted) {
          decryptBuf =
              readCipher(viewUint8List(readBuffer.data, 0, decryptBlockSize));
        }
        BinaryPacket binaryPacket =
            BinaryPacket(encrypted ? decryptBuf : readBuffer.data);
        packetLen = 4 + binaryPacket.length + packetMacLen;
        padding = binaryPacket.padding;
      }
      if (readBuffer.data.length < packetLen) return;
      if (encrypted) {
        decryptBuf = appendUint8List(
            decryptBuf,
            readCipher(viewUint8List(readBuffer.data, decryptBlockSize,
                packetLen - decryptBlockSize - packetMacLen)));
      }
      sequenceNumberS2c++;
      if (encrypted && packetMacLen != 0) {
        Uint8List mac = computeMAC(
            MAC.mac(macIdS2c),
            macLenS,
            viewUint8List(decryptBuf, 0, packetLen - packetMacLen),
            sequenceNumberS2c - 1,
            integrityS2c,
            macPrefixS2c);
        if (!equalUint8List(
            mac,
            viewUint8List(
                readBuffer.data, packetLen - packetMacLen, packetMacLen))) {
          throw FormatException('$hostport: verify MAC failed');
        }
      }

      Uint8List packet = encrypted ? decryptBuf : readBuffer.data;
      packetS = SerializableInput(viewUint8List(packet, BinaryPacket.headerSize,
          packetLen - BinaryPacket.headerSize - packetMacLen - padding));
      if (zreader != null) {
        /// If compression has been negotiated, the 'payload' field (and only it)
        /// will be compressed using the negotiated algorithm.
        /// https://tools.ietf.org/html/rfc4253#section-6.2
        packetS = SerializableInput(zreader.convert(packetS.buffer));
      }
      handlePacket(packet);
      readBuffer.flush(packetLen);
      packetLen = 0;
    }
  }

  /// Consumes the initial Protocol Version Exchange.
  /// https://tools.ietf.org/html/rfc4253#section-4.2
  void handleInitialState() {
    int processed = 0, newlineIndex;
    while ((newlineIndex =
            readBuffer.data.indexOf('\n'.codeUnits[0], processed)) !=
        -1) {
      String line = String.fromCharCodes(viewUint8List(
              readBuffer.data, processed, newlineIndex - processed))
          .trim();
      if (tracePrint != null) tracePrint('$hostport: SSH_INIT: $line');
      processed = newlineIndex + 1;
      if (line.startsWith('SSH-')) {
        verS = line;
        serverVersion = toFloat(line.substring(4));
        state++;
        if (server) sendKeyExchangeInit(false);
        break;
      }
    }
    readBuffer.flush(processed);
  }

  /// https://tools.ietf.org/html/rfc4253#section-7.1
  void handleMSG_KEXINIT(MSG_KEXINIT msg, Uint8List packet) {
    if (tracePrint != null) tracePrint('$hostport: MSG_KEXINIT $msg');

    if (client) {
      guessedS = msg.firstKexPacketFollows;
      kexInitS = packet.sublist(0, packetLen - packetMacLen);
    } else {
      guessedC = msg.firstKexPacketFollows;
      kexInitC = packet.sublist(0, packetLen - packetMacLen);
    }

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

    if (print != null) {
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
    }
    if (tracePrint != null) {
      tracePrint(
          '$hostport: blockSize=$encryptBlockSize,$decryptBlockSize, macLen=$macLenC,$macLenS');
    }
    sendDiffileHellmanInit();
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
        deriveKey(kexHash, sessionId, exH, K, 'A'.codeUnits[0], 24),
        deriveKey(kexHash, sessionId, exH, K, 'C'.codeUnits[0], keyLenC),
        true);
    decrypt = initCipher(
        cipherIdS2c,
        deriveKey(kexHash, sessionId, exH, K, 'B'.codeUnits[0], 24),
        deriveKey(kexHash, sessionId, exH, K, 'D'.codeUnits[0], keyLenS),
        false);
    if ((macLenC = MAC.hashSize(macIdC2s)) <= 0) {
      throw FormatException('$hostport: invalid maclen $encryptBlockSize');
    } else if ((macLenS = MAC.hashSize(macIdS2c)) <= 0) {
      throw FormatException('$hostport: invalid maclen $encryptBlockSize');
    }
    integrityC2s =
        deriveKey(kexHash, sessionId, exH, K, 'E'.codeUnits[0], macLenC);
    integrityS2c =
        deriveKey(kexHash, sessionId, exH, K, 'F'.codeUnits[0], macLenS);
    if (server) {
      BlockCipher tmpBC = encrypt;
      encrypt = decrypt;
      decrypt = tmpBC;

      Uint8List swapUL = integrityC2s;
      integrityC2s = integrityS2c;
      integrityS2c = swapUL;
    }
    state = SSHClientState.NEWKEYS;
  }

  void computeTheExchangeHash(Uint8List kS) {
    exH = computeExchangeHash(server, kexMethod, kexHash, verC, verS, kexInitC,
        kexInitS, kS, K, dh, ecdh, x25519dh);

    /// The exchange hash H from the first key exchange is used as the session identifier.
    if (state == SSHClientState.FIRST_KEXREPLY) sessionId = exH;

    if (tracePrint != null) {
      tracePrint('$hostport: H = "${hex.encode(exH)}"');
    }
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
    cipher.init(
        dir,
        ParametersWithIV(
            KeyParameter(key), viewUint8List(IV, 0, cipher.blockSize)));
    return cipher;
  }

  Uint8List readCipher(Uint8List m) => applyBlockCipher(decrypt, m);

  void writeCipher(SSHMessage msg) {
    sequenceNumberC2s++;
    Uint8List m = msg.toBytes(zwriter, random, encryptBlockSize);
    Uint8List encM = applyBlockCipher(encrypt, m);
    Uint8List mac = computeMAC(MAC.mac(macIdC2s), macLenC, m,
        sequenceNumberC2s - 1, integrityC2s, macPrefixC2s);
    socket.sendRaw(Uint8List.fromList(encM + mac));
    if (tracePrint != null) {
      tracePrint('$hostport: sent MSG id=${msg.id}');
    }
  }

  void writeClearOrEncrypted(SSHMessage msg) {
    if (state > SSHClientState.FIRST_NEWKEYS) return writeCipher(msg);
    sequenceNumberC2s++;
    socket.sendRaw(msg.toBytes(null, random, encryptBlockSize));
    if (tracePrint != null) {
      tracePrint('$hostport: sent MSG id=${msg.id} in clear');
    }
  }
}
