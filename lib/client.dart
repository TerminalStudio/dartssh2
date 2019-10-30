// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:math';
import 'dart:collection';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import "package:pointycastle/api.dart";
import 'package:pointycastle/digests/sha1.dart';
import "package:pointycastle/digests/sha256.dart";
import 'package:pointycastle/macs/hmac.dart';
import 'package:validators/sanitizers.dart';

import 'package:dartssh/protocol.dart';
import 'package:dartssh/serializable.dart';
import 'package:dartssh/socket.dart';
import 'package:dartssh/socket_html.dart'
    if (dart.library.io) 'package:dartssh/socket_io.dart';
import 'package:dartssh/ssh.dart';
import 'package:dartssh/zlib.dart';

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

class Identity {
  RSAKey rsa;
  /*ECPair ec;
  Ed25519Pair ed25519;*/
}

class Channel {
  int localId, remoteId, windowC = 0, windowS = 0;
  bool opened = true, agentChannel = false, sentEof = false, sentClose = false;
  Uint8List buf;
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

class SSHClient {
  String hostport, user, termvar, startupCommand;
  bool compress, agentForwarding, closeOnDisconnect, startShell;
  List<Forward> forwardLocal, forwardRemote;
  StringCallback response, print, debugPrint, tracePrint;
  FingerprintCallback hostFingerprint;
  RemoteForwardCallback remoteForward;
  Uint8ListFunction getPassword;
  IdentityFunction loadIdentity;
  VoidCallback success;
  Random random;

  String verC = 'SSH-2.0-dartssh_1.0', verS, login;

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
      nextChannelId = 1,
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

  SocketInterface socket;
  QueueBuffer readBuffer = QueueBuffer(Uint8List(0));
  SerializableInput packetS;
  Uint8List kexInitC,
      kexInitS,
      decryptBuf,
      hText,
      sessionId,
      integrityC2s,
      integrityS2c,
      pw;

  DiffieHellman dh = DiffieHellman();
  EllipticCurveDiffieHellman ecdh = EllipticCurveDiffieHellman();
  X25519DiffieHellman x25519dh = X25519DiffieHellman();
  Digest kexHash;
  BigInt K;
  BlockCipher encrypt, decrypt;
  HMac macAlgoC2s, macAlgoS2c;
  Identity identity;
  Channel sessionChannel;
  HashMap<int, Channel> channels = HashMap<int, Channel>();

  int initialWindowSize = 1048576,
      maxPacketSize = 32768,
      termWidth = 80,
      termHeight = 25;
  dynamic zreader;
  dynamic zwriter;
  HashMap<int, Forward> forwardingRemote;

  SSHClient(
      {this.hostport,
      this.user,
      this.termvar = '',
      this.startupCommand,
      this.compress = false,
      this.agentForwarding = false,
      this.closeOnDisconnect,
      this.startShell = true,
      this.forwardLocal,
      this.forwardRemote,
      this.response,
      this.print,
      this.debugPrint,
      this.tracePrint,
      this.success,
      this.hostFingerprint,
      this.loadIdentity,
      this.getPassword,
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
        packetS = SerializableInput(zreader.convert(packetS.buffer));
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
      String line = String.fromCharCodes(viewUint8List(
              readBuffer.data, processed, newlineIndex - processed))
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

      case MSG_SERVICE_ACCEPT.ID:
        handleMSG_SERVICE_ACCEPT();
        break;

      case MSG_USERAUTH_FAILURE.ID:
        handleMSG_USERAUTH_FAILURE(
            MSG_USERAUTH_FAILURE()..deserialize(packetS));
        break;

      case MSG_USERAUTH_SUCCESS.ID:
        handleMSG_USERAUTH_SUCCESS();
        break;

      case MSG_USERAUTH_INFO_REQUEST.ID:
        handleMSG_USERAUTH_INFO_REQUEST(
            MSG_USERAUTH_INFO_REQUEST()..deserialize(packetS));
        break;

      case MSG_GLOBAL_REQUEST.ID:
        handleMSG_GLOBAL_REQUEST(MSG_GLOBAL_REQUEST()..deserialize(packetS));
        break;

      case MSG_CHANNEL_OPEN.ID:
        handleMSG_CHANNEL_OPEN(MSG_CHANNEL_OPEN()..deserialize(packetS));
        break;

      case MSG_CHANNEL_OPEN_CONFIRMATION.ID:
        handleMSG_CHANNEL_OPEN_CONFIRMATION(
            MSG_CHANNEL_OPEN_CONFIRMATION()..deserialize(packetS));
        break;

      case MSG_CHANNEL_WINDOW_ADJUST.ID:
        handleMSG_CHANNEL_WINDOW_ADJUST(
            MSG_CHANNEL_WINDOW_ADJUST()..deserialize(packetS));
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

      case MSG_CHANNEL_REQUEST.ID:
        handleMSG_CHANNEL_REQUEST(MSG_CHANNEL_REQUEST()..deserialize(packetS));
        break;

      case MSG_CHANNEL_SUCCESS.ID:
        if (tracePrint != null) {
          tracePrint('$hostport: MSG_CHANNEL_SUCCESS');
        }
        break;

      case MSG_CHANNEL_FAILURE.ID:
        if (tracePrint != null) {
          tracePrint('$hostport: MSG_CHANNEL_FAILURE');
        }
        break;

      case MSG_DISCONNECT.ID:
        handleMSG_DISCONNECT(MSG_DISCONNECT()..deserialize(packetS));
        break;

      case MSG_IGNORE.ID:
        handleMSG_IGNORE(MSG_IGNORE()..deserialize(packetS));
        break;

      case MSG_DEBUG.ID:
        handleMSG_DEBUG(MSG_DEBUG()..deserialize(packetS));
        break;

      default:
        if (print != null) {
          print('$hostport: unknown packet number: $packetId, len $packetLen');
        }
        break;
    }
  }

  void handleMSG_KEXINIT(MSG_KEXINIT msg, Uint8List packet) {
    if (tracePrint != null) tracePrint('$hostport: MSG_KEXINIT $msg');

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

    if (KEX.x25519DiffieHellman(kexMethod)) {
      kexHash = SHA256Digest();
      x25519dh.GeneratePair(random);
      writeClearOrEncrypted(MSG_KEX_ECDH_INIT(x25519dh.myPubKey));
    } else if (KEX.ellipticCurveDiffieHellman(kexMethod)) {
      kexHash = KEX.ellipticCurveHash(kexMethod);
      ecdh = EllipticCurveDiffieHellman(
          KEX.ellipticCurve(kexMethod), KEX.ellipticCurveSecretBits(kexMethod));
      ecdh.generatePair(random);
      writeClearOrEncrypted(MSG_KEX_ECDH_INIT(ecdh.cText));
    } else if (KEX.diffieHellmanGroupExchange(kexMethod)) {
      if (kexMethod == KEX.DHGEX_SHA1) {
        kexHash = SHA1Digest();
      } else if (kexMethod == KEX.DHGEX_SHA256) {
        kexHash = SHA256Digest();
      }
      writeClearOrEncrypted(
          MSG_KEX_DH_GEX_REQUEST(dh.gexMin, dh.gexMax, dh.gexPref));
    } else if (KEX.diffieHellman(kexMethod)) {
      if (kexMethod == KEX.DH14_SHA1) {
        dh = DiffieHellman.group14();
      } else if (kexMethod == KEX.DH1_SHA1) {
        dh = DiffieHellman.group1();
      }
      kexHash = SHA1Digest();
      dh.generatePair(random);
      writeClearOrEncrypted(MSG_KEXDH_INIT(dh.e));
    } else {
      throw FormatException('$hostport: unknown kex method: $kexMethod');
    }
  }

  void handleMSG_KEXDH_REPLY(int packetId, Uint8List packet) {
    if (state != SSHClientState.FIRST_KEXREPLY &&
        state != SSHClientState.KEXREPLY) {
      throw FormatException('$hostport: unexpected state $state');
    }
    if (guessedS && !guessedRightS) {
      guessedS = false;
      if (print != null) {
        print('$hostport: server guessed wrong, ignoring packet');
      }
      return;
    }

    Uint8List fingerprint;
    if (packetId == MSG_KEX_ECDH_REPLY.ID &&
        KEX.x25519DiffieHellman(kexMethod)) {
      fingerprint = handleX25519MSG_KEX_ECDH_REPLY(
              MSG_KEX_ECDH_REPLY()..deserialize(packetS)) ??
          fingerprint;
    } else if (packetId == MSG_KEXDH_REPLY.ID &&
        KEX.ellipticCurveDiffieHellman(kexMethod)) {
      fingerprint = handleEcDhMSG_KEX_ECDH_REPLY(
              MSG_KEX_ECDH_REPLY()..deserialize(packetS)) ??
          fingerprint;
    } else if (packetId == MSG_KEXDH_REPLY.ID &&
        KEX.diffieHellmanGroupExchange(kexMethod)) {
      handleDhGroupMSG_KEX_DH_GEX_GROUP(
          MSG_KEX_DH_GEX_GROUP()..deserialize(packetS));
      return;
    } else {
      fingerprint =
          handleDhMSG_KEXDH_REPLY(MSG_KEXDH_REPLY()..deserialize(packetS)) ??
              fingerprint;
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
    if (tracePrint != null) {
      tracePrint('$hostport: MSG_KEX_ECDH_REPLY for X25519DH');
    }
    if (!acceptedHostkey) fingerprint = msg.kS;

    x25519dh.remotePubKey = msg.qS;
    K = x25519dh.computeSecret();
    if (!computeExchangeHashAndVerifyHostKey(msg.kS, msg.hSig)) {
      throw FormatException('$hostport: verify hostkey failed');
    }

    return fingerprint;
  }

  Uint8List handleEcDhMSG_KEX_ECDH_REPLY(MSG_KEX_ECDH_REPLY msg) {
    Uint8List fingerprint;
    if (tracePrint != null) {
      tracePrint('$hostport: MSG_KEX_ECDH_REPLY for ECDH');
    }
    if (!acceptedHostkey) fingerprint = msg.kS;

    K = ecdh.computeSecret(msg.qS);
    if (!computeExchangeHashAndVerifyHostKey(msg.kS, msg.hSig)) {
      throw FormatException('$hostport: verify hostkey failed');
    }

    return fingerprint;
  }

  void handleDhGroupMSG_KEX_DH_GEX_GROUP(MSG_KEX_DH_GEX_GROUP msg) {
    if (tracePrint != null) {
      tracePrint('$hostport: MSG_KEX_DH_GEX_GROUP');
    }
    dh = DiffieHellman(msg.p, msg.g, 256);
    dh.generatePair(random);
    writeClearOrEncrypted(MSG_KEX_DH_GEX_INIT(dh.e));
  }

  Uint8List handleDhMSG_KEXDH_REPLY(MSG_KEXDH_REPLY msg) {
    Uint8List fingerprint;
    if (tracePrint != null) {
      tracePrint('$hostport: MSG_KEXDH_REPLY');
    }
    if (!acceptedHostkey) fingerprint = msg.kS;

    K = dh.computeSecret(msg.f);
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

  void handleMSG_SERVICE_ACCEPT() {
    if (tracePrint != null) tracePrint('$hostport: MSG_SERVICE_ACCEPT');
    login = user;
    if (login == null || login.isEmpty) {
      loginPrompts = 1;
      response('login: ');
    }
    if (loadIdentity != null) {
      if ((identity = loadIdentity()) != null) return;
    }
    sendAuthenticationRequest();
  }

  void handleMSG_USERAUTH_FAILURE(MSG_USERAUTH_FAILURE msg) {
    if (tracePrint != null) {
      tracePrint(
          '$hostport: MSG_USERAUTH_FAILURE: auth_left="${msg.authLeft}" loadedPw=$loadedPw useauthFail=$userauthFail');
    }
    if (!loadedPw) clearPassword();
    userauthFail++;
    if (userauthFail == 1 && !wrotePw) {
      response('Password:');
      passwordPrompts = 1;
      loadPassword();
    } else {
      throw FormatException('$hostport: authorization failed');
    }
  }

  void handleMSG_USERAUTH_SUCCESS() {
    if (tracePrint != null) {
      tracePrint('$hostport: MSG_USERAUTH_SUCCESS');
    }
    sessionChannel = Channel(nextChannelId);
    sessionChannel.windowS = initialWindowSize;
    channels[nextChannelId] = sessionChannel;
    nextChannelId++;

    if (compressIdC2s == Compression.OpenSSHZLib) {
      // zwriter = ArchiveDeflateWriter();
      throw FormatException('compression not supported');
    }
    if (compressIdS2c == Compression.OpenSSHZLib) {
      // zreader = ArchiveInflateReader();
      throw FormatException('compression not supported');
    }
    if (success != null) success();
    writeCipher(MSG_CHANNEL_OPEN.create(
        'session', sessionChannel.localId, initialWindowSize, maxPacketSize));
  }

  void handleMSG_USERAUTH_INFO_REQUEST(MSG_USERAUTH_INFO_REQUEST msg) {
    if (tracePrint != null) {
      tracePrint(
          '$hostport: MSG_USERAUTH_INFO_REQUEST prompts=${msg.prompts.length}');
    }
    if (msg.instruction.isNotEmpty) {
      if (tracePrint != null) {
        tracePrint('$hostport: instruction: ${msg.instruction}');
      }
      response(msg.instruction);
    }

    for (MapEntry<String, int> prompt in msg.prompts) {
      if (tracePrint != null) {
        tracePrint('$hostport: prompt: ${prompt.key}');
      }
      response(prompt.key);
    }

    if (msg.prompts.isNotEmpty) {
      passwordPrompts = msg.prompts.length;
      loadPassword();
    } else {
      writeCipher(MSG_USERAUTH_INFO_RESPONSE(List<Uint8List>()));
    }
  }

  void handleMSG_GLOBAL_REQUEST(MSG_GLOBAL_REQUEST msg) {
    if (tracePrint != null) {
      tracePrint('$hostport: MSG_GLOBAL_REQUEST request=${msg.request}');
    }
  }

  void handleMSG_CHANNEL_OPEN(MSG_CHANNEL_OPEN msg) {
    /**/
  }

  void handleMSG_CHANNEL_OPEN_CONFIRMATION(MSG_CHANNEL_OPEN_CONFIRMATION msg) {
    if (tracePrint != null) {
      tracePrint(
          '$hostport: MSG_CHANNEL_OPEN_CONFIRMATION local_id=${msg.recipientChannel} remote_id=${msg.senderChannel}');
    }

    Channel chan = channels[msg.recipientChannel];
    if (chan == null || chan.remoteId == null) {
      throw FormatException('$hostport: open invalid channel');
    }
    chan.remoteId = msg.senderChannel;
    chan.windowC = msg.initialWinSize;
    chan.opened = true;
    if (chan == sessionChannel) {
      if (agentForwarding) {
        writeCipher(MSG_CHANNEL_REQUEST.exec(
            chan.remoteId, 'auth-agent-req@openssh.com', '', true));
      }

      if (forwardRemote != null) {
        for (Forward forward in forwardRemote) {
          writeCipher(MSG_GLOBAL_REQUEST_TCPIP('', forward.port));
          forwardingRemote[forward.port] = forward;
        }
      }

      if (startShell) {
        writeCipher(MSG_CHANNEL_REQUEST.ptyReq(
            chan.remoteId,
            'pty-req',
            Point(termWidth, termHeight),
            Point(termWidth * 8, termHeight * 12),
            termvar,
            '',
            true));

        writeCipher(MSG_CHANNEL_REQUEST.exec(chan.remoteId, 'shell', '', true));

        if ((startupCommand ?? '').isNotEmpty) {
          sendToChannel(sessionChannel, utf8.encode(startupCommand));
        }
      }
    } else if (chan.cb != null) {
      chan.cb(chan, Uint8List(0));
    }
  }

  void handleMSG_CHANNEL_WINDOW_ADJUST(MSG_CHANNEL_WINDOW_ADJUST msg) {
    if (tracePrint != null) {
      tracePrint(
          '$hostport: MSG_CHANNEL_WINDOW_ADJUST add ${msg.bytesToAdd} to channel ${msg.recipientChannel}');
    }
    Channel chan = channels[msg.recipientChannel];
    if (chan == null) {
      throw FormatException('$hostport: window adjust invalid channel');
    }
    chan.windowC += msg.bytesToAdd;
  }

  void handleMSG_CHANNEL_DATA(MSG_CHANNEL_DATA msg) {
    if (tracePrint != null) {
      tracePrint(
          '$hostport: MSG_CHANNEL_DATA: channel ${msg.recipientChannel} : ${msg.data.length} bytes');
    }
    Channel chan = channels[msg.recipientChannel];
    if (chan == null) {
      throw FormatException('$hostport: data for invalid channel');
    }
    chan.windowS -= (packetLen - packetMacLen - 4);
    if (chan.windowS < initialWindowSize ~/ 2) {
      writeClearOrEncrypted(
          MSG_CHANNEL_WINDOW_ADJUST(chan.remoteId, initialWindowSize));
      chan.windowS += initialWindowSize;
    }

    if (chan == sessionChannel) {
      response(utf8.decode(msg.data));
    } else if (chan.cb != null) {
      chan.cb(chan, msg.data);
    } else if (chan.agentChannel) {
      /**/
    }
  }

  void handleMSG_CHANNEL_EOF(MSG_CHANNEL_EOF msg) {
    if (tracePrint != null) {
      tracePrint('$hostport: MSG_CHANNEL_EOF ${msg.recipientChannel}');
    }
    Channel chan = channels[msg.recipientChannel];
    if (chan == null) {
      throw FormatException('$hostport: close invalid channel');
    }
    if (!chan.sentEof) {
      chan.sentEof = true;
      writeCipher(MSG_CHANNEL_EOF(chan.remoteId));
    }
  }

  void handleMSG_CHANNEL_CLOSE(MSG_CHANNEL_CLOSE msg) {
    if (tracePrint != null) {
      tracePrint('$hostport: MSG_CHANNEL_CLOSE ${msg.recipientChannel}');
    }
    Channel chan = channels[msg.recipientChannel];
    if (chan == null) {
      throw FormatException('$hostport: EOF invalid channel');
    }

    bool alreadySentClose = chan.sentClose;
    if (!alreadySentClose) {
      chan.sentClose = true;
      writeCipher(MSG_CHANNEL_CLOSE(chan.remoteId));
    }
    if (chan == sessionChannel) {
      writeCipher(MSG_DISCONNECT());
      sessionChannel = null;
    } else if (!alreadySentClose && chan.cb != null) {
      chan.opened = false;
      chan.cb(chan, Uint8List(0));
    }
    channels.remove(msg.recipientChannel);
  }

  void handleMSG_CHANNEL_REQUEST(MSG_CHANNEL_REQUEST msg) {
    if (tracePrint != null) {
      tracePrint(
          '$hostport: MSG_CHANNEL_REQUEST ${msg.requestType} wantReply=${msg.wantReply}');
    }
  }

  void handleMSG_DISCONNECT(MSG_DISCONNECT msg) {
    if (tracePrint != null) {
      tracePrint(
          '$hostport: MSG_DISCONNECT ${msg.reasonCode} ${msg.description}');
    }
  }

  void handleMSG_IGNORE(MSG_IGNORE msg) {
    if (tracePrint != null) {
      tracePrint('$hostport: MSG_IGNORE');
    }
  }

  void handleMSG_DEBUG(MSG_DEBUG msg) {
    if (tracePrint != null) {
      tracePrint('$hostport: MSG_DEBUG ${msg.message}');
    }
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
    cipher.init(
        dir,
        ParametersWithIV(
            KeyParameter(key), viewUint8List(IV, 0, cipher.blockSize)));
    return cipher;
  }

  Uint8List readCipher(Uint8List m) {
    Uint8List decM = Uint8List(m.length);
    assert(m.length % decryptBlockSize == 0);
    for (int offset = 0; offset < m.length; offset += encryptBlockSize) {
      decrypt.processBlock(m, offset, decM, offset);
    }
    return decM;
  }

  void writeCipher(SSHMessage msg) {
    sequenceNumberC2s++;
    Uint8List m = msg.toBytes(zwriter, random, encryptBlockSize),
        encM = Uint8List(m.length);
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

  void loadPassword() {
    if (getPassword != null && (pw = getPassword()) != null) sendPassword();
  }

  void clearPassword() {
    if (pw == null) return;
    for (int i = 0; i < pw.length; i++) {
      pw[i] ^= random.nextInt(255);
    }
    pw = null;
  }

  void sendPassword() {
    response('\r\n');
    wrotePw = true;
    if (userauthFail != 0) {
      writeCipher(MSG_USERAUTH_REQUEST(
          login, 'ssh-connection', 'password', '', pw, Uint8List(0)));
    } else {
      List<Uint8List> prompt =
          List<Uint8List>.filled(passwordPrompts, Uint8List(0));
      prompt.last = pw;
      writeCipher(MSG_USERAUTH_INFO_RESPONSE(prompt));
    }
    passwordPrompts = 0;
    clearPassword();
  }

  void sendAuthenticationRequest() {
    if (identity == null) {
      // do nothing
    }
    /*else if (identity->ed25519.privkey.size()) {
      string pubkey = SSH::Ed25519Key(identity->ed25519.pubkey).ToString();
      string challenge = SSH::DeriveChallengeText(session_id, login, "ssh-connection", "publickey", "ssh-ed25519", pubkey);
      string sig = SSH::Ed25519Signature(Ed25519Sign(challenge, identity->ed25519.privkey)).ToString();
      if (!WriteCipher(c, SSH::MSG_USERAUTH_REQUEST(login, "ssh-connection", "publickey", "ssh-ed25519", pubkey, sig)))
        return ERRORv(-1, c->Name(), ": write");
      return 0;
    } else if (identity->ec) {
    } else if (identity->rsa) {
    }*/
    writeCipher(MSG_USERAUTH_REQUEST(login, 'ssh-connection',
        'keyboard-interactive', '', Uint8List(0), Uint8List(0)));
  }

  void sendToChannel(Channel chan, Uint8List b) {
    writeCipher(MSG_CHANNEL_DATA(chan.remoteId, b));
    chan.windowC -= (b.length - 4);
  }

  void sendChannelData(Uint8List b) {
    if (loginPrompts != 0) {
      response(utf8.decode(b));
      bool cr = b.isNotEmpty && b.last == '\n'.codeUnits[0];
      login += String.fromCharCodes(b, 0, b.length - (cr ? 1 : 0));
      if (cr) {
        response('\n');
        loginPrompts = 0;
        sendAuthenticationRequest();
      }
    } else if (passwordPrompts != 0) {
      bool cr = b.isNotEmpty && b.last == '\n'.codeUnits[0];
      pw = appendUint8List(
          pw ?? Uint8List(0), viewUint8List(b, 0, b.length - (cr ? 1 : 0)));
      if (cr) sendPassword();
    } else {
      if (sessionChannel != null) {
        sendToChannel(sessionChannel, b);
      }
    }
  }
}
