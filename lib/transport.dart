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
typedef FutureFunction = Future Function();
typedef StringCallback = void Function(String?);
typedef StringFunction = String Function();
typedef StringFilter = String Function(String?);
typedef Uint8ListCallback = void Function(Uint8List);
typedef Uint8ListFunction = Uint8List? Function();
typedef IdentityFunction = Identity? Function();
typedef FingerprintCallback = bool Function(int, Uint8List?);
typedef ChannelCallback = void Function(Channel, Uint8List?);
typedef ChannelInputCallback = void Function(Channel, SerializableInput);
typedef ResponseCallback = void Function(SSHTransport, Uint8List);
typedef RemoteForwardCallback = Future<String?> Function(
    Channel, String?, int?, String?, int?);

/// When a connection comes to a port for which forwarding has been
/// requested, a channel is opened to forward the port to the other side.
class Forward {
  int? port, targetPort;
  String? targetHost;
}

/// All terminal sessions, forwarded connections, etc., are [Channel]s.
/// Multiple [Channel]s are multiplexed into a single connection and
/// [Channel]s are flow-controlled.  No data may be sent to a channel until
/// a message is received to indicate that window space is available.
class Channel {
  int localId, remoteId, windowC, windowS;
  bool opened = true, agentChannel = false, sentEof = false, sentClose = false;
  QueueBuffer buf = QueueBuffer(Uint8List(0));
  ChannelCallback? cb;
  StringCallback? error;
  VoidCallback? connected, closed;
  Channel({
    this.localId = 0,
    this.remoteId = 0,
    this.windowC = 0,
    this.windowS = 0,
    this.cb,
    this.error,
    this.connected,
    this.closed,
  });
}

/// It is RECOMMENDED that the keys be changed after each gigabyte of transmitted
/// data or after each hour of connection time, whichever comes sooner.
enum SSHTransportState {
  INIT,
  FIRST_KEXINIT,
  FIRST_KEXREPLY,
  FIRST_NEWKEYS,
  KEXINIT,
  KEXREPLY,
  NEWKEYS,
}

// extension SSHTransportStateX on SSHTransportState {
//   operator <(SSHTransportState other) => this.index < other.index;
//   operator >(SSHTransportState other) => this.index > other.index;
//   operator <=(SSHTransportState other) => this.index <= other.index;
//   operator >=(SSHTransportState other) => this.index >= other.index;
// }

/// SSH Transport Layer Protocol implementation providing KEX, ciphers, and MAC.
/// https://tools.ietf.org/html/rfc4253
abstract class SSHTransport with SSHDiffieHellman {
  /// Parameter for public key authentication
  Identity? identity;

  /// Remote endpoint of SSH connection.  Parameter on client-side.
  Uri? hostport;

  /// Whether compression is supported.
  bool? compress;

  /// Source of randomness, e.g [Random.secure()].
  final Random random;

  /// Pointycastle's random interface.
  SecureRandom? secureRandom;

  /// Parameter invoked on connection close.
  VoidCallback? disconnected;

  /// Parameter invoked with session channel data (and optionally UI prompts).
  ResponseCallback? response;

  /// Parameter invoked with ERROR and INFO loggging.
  StringCallback? print;

  /// Parameter invoked with debug logging.
  StringCallback? debugPrint;

  /// Parameter invoked with trace logging.
  StringCallback? tracePrint;

  /// Parameter describing local ports to forward over SSH tunnel.
  List<Forward>? forwardLocal;

  /// Parameter describing remote ports to forward over SSH tunnel.
  List<Forward>? forwardRemote;

  /// Paramter invoked upon connection to forwarded remote port.
  RemoteForwardCallback? remoteForward;

  // State
  bool? server,
      guessedC = false,
      guessedS = false,
      guessedRightC = false,
      guessedRightS = false;

  var state = SSHTransportState.INIT;

  var padding = 0;
  var packetId = 0;
  var packetLen = 0;
  var packetMacLen = 0;
  var hostkeyType = 0;
  var kexMethod = 0;
  var macPrefixC2s = 0;
  var macPrefixS2c = 0;
  var macHashLenC = 0;
  var macHashLenS = 0;
  var macIdC2s = 0;
  var macIdS2c = 0;
  var cipherIdC2s = 0;
  var cipherIdS2c = 0;
  var compressIdC2s = 0;
  var compressIdS2c = 0;
  var encryptBlockSize = 0;
  var decryptBlockSize = 0;
  var sequenceNumberC2s = 0;
  var sequenceNumberS2c = 0;
  var nextChannelId = 1;
  var maxPacketSize = 32768;
  var initialWindowSize = 1048576;

  num serverVersion = 0;

  final verC = 'SSH-2.0-dartssh_1.0';
  String? verS;

  Uint8List? kexInitC;
  Uint8List? kexInitS;
  Uint8List? decryptBuf;
  Uint8List? exH;
  Uint8List? sessionId;
  Uint8List? integrityC2s;
  Uint8List? integrityS2c;

  SocketInterface? socket;
  QueueBuffer readBuffer = QueueBuffer(Uint8List(0));
  SerializableInput? packetS;
  BlockCipher? encrypt, decrypt;
  HMac? macAlgoC2s, macAlgoS2c;
  dynamic zreader, zwriter;
  Channel? sessionChannel;
  HashMap<int, Channel> channels = HashMap<int, Channel>();
  HashMap<int?, Forward>? forwardingRemote;

  SSHTransport(
    this.server, {
    this.identity,
    this.hostport,
    this.compress,
    this.forwardLocal,
    this.forwardRemote,
    this.disconnected,
    this.response,
    this.print,
    this.debugPrint,
    this.tracePrint,
    this.socket,
    Random? random,
    this.secureRandom,
  }) : random = random ?? Random.secure();

  // Interface
  void sendDiffileHellmanInit();
  void sendChannelData(Uint8List b);
  void handlePacket(Uint8List packet);
  void handleChannelOpenConfirmation(Channel chan);
  void handleChannelData(Channel chan, Uint8List data);
  void handleChannelClose(Channel chan, [String? description]);

  /// Whether we've initiated the connection.
  bool get client => !server!;

  /// PointyCastle random number generator interface.
  SecureRandom getSecureRandom() {
    if (secureRandom != null) return secureRandom!;
    return (secureRandom = FortunaRandom())
      ..seed(KeyParameter(randBytes(random, 32)));
  }

  /// If anything goes wrong, disconnect with [reason].
  void disconnect(String reason) {
    if (socket != null) {
      socket!.close();
      socket = null;
    }

    channels.forEach((int channelId, Channel channel) {
      if (!channel.sentClose && channel.closed != null) channel.closed!();
    });
    channels.clear();

    debugPrint?.call('SSHTransport.disconnected: $reason');

    if (disconnected != null) disconnected!();
  }

  /// Callback supplied to [socket.connect].
  void onConnected() {
    socket!.handleError((error) => disconnect('SSHTransport.error: $error'));
    socket!.handleDone((v) => disconnect('SSHTransport.done: $v'));
    socket!.listen(handleRead);
    handleConnected();
  }

  /// When the connection has been established, both sides MUST send an identification string.
  /// https://tools.ietf.org/html/rfc4253#section-4.2
  void handleConnected() {
    debugPrint?.call('SSHTransport.handleConnected');
    if (state != SSHTransportState.INIT) throw FormatException('$state');
    socket!.send(verC + '\r\n');
    tracePrint?.call('-> $hostport $verC');
    if (client) sendKeyExchangeInit(false);
  }

  /// Key exchange begins by each side sending SSH_MSG_KEXINIT.
  void sendKeyExchangeInit(bool guess) {
    final keyPref = Key.preferenceCsv();
    final kexPref = KEX.preferenceCsv();
    final cipherPref = Cipher.preferenceCsv();
    final macPref = MAC.preferenceCsv();
    final compressPref = Compression.preferenceCsv(compress! ? 0 : 1);

    sequenceNumberC2s++;

    final kexInit = MSG_KEXINIT(
      randBytes(random, 16),
      kexPref,
      keyPref,
      cipherPref,
      cipherPref,
      macPref,
      macPref,
      compressPref,
      compressPref,
      '',
      '',
      guess,
    ).toBytes(null, random, 8);

    if (client) {
      kexInitC = kexInit;
    } else {
      kexInitS = kexInit;
    }

    socket!.sendRaw(kexInit);

    debugPrint?.call(
      '-> $hostport KEXINIT { kex=$kexPref key=$keyPref, cipher=$cipherPref, mac=$macPref, compress=$compressPref }',
    );
  }

  /// Callback supplied to [socket.listen].
  void handleRead(Uint8List dataChunk) {
    readBuffer.add(dataChunk);

    /// Initialze with an ASCII version exchange.
    if (state == SSHTransportState.INIT) {
      handleInitialState();
      if (state == SSHTransportState.INIT) return;
    }

    /// Thereafter we speak RFC4253 Binary Packet Protocol.
    while (true) {
      bool encrypted = state.index > SSHTransportState.FIRST_NEWKEYS.index;

      /// We only need to decrypt one cipher block to determine the next packet length.
      if (packetLen == 0) {
        packetMacLen = macHashLenS != 0
            ? (macPrefixS2c != 0 ? macPrefixS2c : macHashLenS)
            : 0;
        if (readBuffer.data.length < BinaryPacket.headerSize ||
            (encrypted && readBuffer.data.length < decryptBlockSize)) {
          return;
        }
        if (encrypted) {
          decryptBuf =
              readCipher(viewUint8List(readBuffer.data, 0, decryptBlockSize));
        }
        BinaryPacket binaryPacket =
            BinaryPacket(encrypted ? decryptBuf! : readBuffer.data);
        packetLen = 4 + binaryPacket.length + packetMacLen;
        padding = binaryPacket.padding;
      }

      /// Wait until we've read the entire packet.
      if (readBuffer.data.length < packetLen) return;

      /// Decrypts the remaining cipher blocks in the packet.
      if (encrypted) {
        decryptBuf = appendUint8List(
            decryptBuf!,
            readCipher(viewUint8List(readBuffer.data, decryptBlockSize,
                packetLen - decryptBlockSize - packetMacLen)));
      }

      /// Verifies the Message Authentication Code (MAC).
      sequenceNumberS2c++;
      if (encrypted && packetMacLen != 0) {
        Uint8List mac = computeMAC(
            MAC.mac(macIdS2c),
            macHashLenS,
            viewUint8List(decryptBuf!, 0, packetLen - packetMacLen),
            sequenceNumberS2c - 1,
            integrityS2c!,
            macPrefixS2c);
        if (!equalUint8List(
            mac,
            viewUint8List(
                readBuffer.data, packetLen - packetMacLen, packetMacLen))) {
          throw FormatException('$hostport: verify MAC failed');
        }
      }

      /// Handles the packet.
      Uint8List packet = encrypted ? decryptBuf! : readBuffer.data;
      packetS = SerializableInput(viewUint8List(packet, BinaryPacket.headerSize,
          packetLen - BinaryPacket.headerSize - packetMacLen - padding));
      if (zreader != null) {
        /// If compression has been negotiated, the 'payload' field (and only it)
        /// will be compressed using the negotiated algorithm.
        /// https://tools.ietf.org/html/rfc4253#section-6.2
        packetS = SerializableInput(zreader.convert(packetS!.buffer));
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
      final line = String.fromCharCodes(
        viewUint8List(readBuffer.data, processed, newlineIndex - processed),
      ).trim();
      tracePrint?.call('<- $hostport: SSH_INIT: $line');
      processed = newlineIndex + 1;
      if (line.startsWith('SSH-')) {
        verS = line;
        serverVersion = toFloat(line.substring(4));
        state = SSHTransportState.FIRST_KEXINIT;
        if (server!) sendKeyExchangeInit(false);
        break;
      }
    }
    readBuffer.flush(processed);
  }

  /// https://tools.ietf.org/html/rfc4253#section-7.1
  void handleMSG_KEXINIT(MSG_KEXINIT msg, Uint8List packet) {
    tracePrint?.call('<- $hostport: MSG_KEXINIT\n$msg');

    if (client) {
      guessedS = msg.firstKexPacketFollows;
      kexInitS = packet.sublist(0, packetLen - packetMacLen);
    } else {
      guessedC = msg.firstKexPacketFollows;
      kexInitC = packet.sublist(0, packetLen - packetMacLen);
    }

    /// Make sure we can agree on an algorithm suite.
    if (0 ==
        (kexMethod = KEX.preferenceIntersect(msg.kexAlgorithms, server!))) {
      throw FormatException('$hostport: negotiate kex');
    } else if (0 ==
        (hostkeyType =
            Key.preferenceIntersect(msg.serverHostKeyAlgorithms, server!))) {
      throw FormatException('$hostport: negotiate hostkey');
    } else if (0 ==
        (cipherIdC2s = Cipher.preferenceIntersect(
            msg.encryptionAlgorithmsClientToServer, server!))) {
      throw FormatException('$hostport: negotiate c2s cipher');
    } else if (0 ==
        (cipherIdS2c = Cipher.preferenceIntersect(
            msg.encryptionAlgorithmsServerToClient, server!))) {
      throw FormatException('$hostport: negotiate s2c cipher');
    } else if (0 ==
        (macIdC2s = MAC.preferenceIntersect(
            msg.macAlgorithmsClientToServer, server!))) {
      throw FormatException('$hostport: negotiate c2s mac');
    } else if (0 ==
        (macIdS2c = MAC.preferenceIntersect(
            msg.macAlgorithmsServerToClient, server!))) {
      throw FormatException('$hostport: negotiate s2c mac');
    } else if (0 ==
        (compressIdC2s = Compression.preferenceIntersect(
            msg.compressionAlgorithmsClientToServer,
            server!,
            compress! ? 0 : 1))) {
      throw FormatException('$hostport: negotiate c2s compression');
    } else if (0 ==
        (compressIdS2c = Compression.preferenceIntersect(
            msg.compressionAlgorithmsServerToClient,
            server!,
            compress! ? 0 : 1))) {
      throw FormatException('$hostport: negotiate s2c compression');
    }

    /// Setup connection and start Diffie Hellman key exchange.
    guessedRightS = kexMethod == KEX.id(msg.kexAlgorithms!.split(',')[0]) &&
        hostkeyType == Key.id(msg.serverHostKeyAlgorithms!.split(',')[0]);
    guessedRightC = kexMethod == 1 && hostkeyType == 1;
    encryptBlockSize = Cipher.blockSize(cipherIdC2s);
    decryptBlockSize = Cipher.blockSize(cipherIdS2c);
    macAlgoC2s = MAC.mac(macIdC2s);
    macPrefixC2s = MAC.prefixBytes(macIdC2s);
    macAlgoS2c = MAC.mac(macIdS2c);
    macPrefixS2c = MAC.prefixBytes(macIdS2c);
    sendDiffileHellmanInit();

    if (print != null) {
      print!('$hostport: ssh negotiated { kex=${KEX.name(kexMethod)}, hostkey=${Key.name(hostkeyType)}' +
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

    tracePrint?.call(
        '$hostport: blockSize=$encryptBlockSize,$decryptBlockSize, macHashLen=$macHashLenC,$macHashLenS');
  }

  /// When MSG_NEWKEYS is received, the new keys and algorithms MUST be used for receiving.
  void handleMSG_NEWKEYS() {
    if (state != SSHTransportState.FIRST_NEWKEYS &&
        state != SSHTransportState.NEWKEYS) {
      throw FormatException('$hostport: unexpected state $state');
    }

    tracePrint?.call('<- $hostport: MSG_NEWKEYS');

    int keyLenC = Cipher.keySize(cipherIdC2s),
        keyLenS = Cipher.keySize(cipherIdS2c);
    encrypt = initCipher(
        cipherIdC2s,
        deriveKey(kexHash, sessionId, exH, K, 'A'.codeUnits[0], 24),
        deriveKey(kexHash, sessionId, exH, K, 'C'.codeUnits[0], keyLenC),
        client ? true : false);
    decrypt = initCipher(
        cipherIdS2c,
        deriveKey(kexHash, sessionId, exH, K, 'B'.codeUnits[0], 24),
        deriveKey(kexHash, sessionId, exH, K, 'D'.codeUnits[0], keyLenS),
        client ? false : true);
    if ((macHashLenC = MAC.hashSize(macIdC2s)) <= 0) {
      throw FormatException('$hostport: invalid maclen $encryptBlockSize');
    } else if ((macHashLenS = MAC.hashSize(macIdS2c)) <= 0) {
      throw FormatException('$hostport: invalid maclen $encryptBlockSize');
    }
    integrityC2s =
        deriveKey(kexHash, sessionId, exH, K, 'E'.codeUnits[0], macHashLenC);
    integrityS2c =
        deriveKey(kexHash, sessionId, exH, K, 'F'.codeUnits[0], macHashLenS);
    if (server!) {
      BlockCipher? tmpBC = encrypt;
      encrypt = decrypt;
      decrypt = tmpBC;

      Uint8List? swapUL = integrityC2s;
      integrityC2s = integrityS2c;
      integrityS2c = swapUL;
    }
    state = SSHTransportState.NEWKEYS;
  }

  /// If the remote side can open the channel, it responds with SSH_MSG_CHANNEL_OPEN_CONFIRMATION.
  void handleMSG_CHANNEL_OPEN_CONFIRMATION(MSG_CHANNEL_OPEN_CONFIRMATION msg) {
    tracePrint?.call(
        '<- $hostport: MSG_CHANNEL_OPEN_CONFIRMATION local_id=${msg.recipientChannel} remote_id=${msg.senderChannel}');

    Channel? chan = channels[msg.recipientChannel!];
    if (chan == null) {
      throw FormatException('$hostport: open invalid channel');
    }
    chan.remoteId = msg.senderChannel!;
    chan.windowC = msg.initialWinSize!;
    chan.opened = true;
    handleChannelOpenConfirmation(chan);
  }

  /// If the remote side can't open the channel, it responds with SSH_MSG_CHANNEL_OPEN_FAILURE.
  void handleMSG_CHANNEL_OPEN_FAILURE(MSG_CHANNEL_OPEN_FAILURE msg) {
    tracePrint?.call(
        '<- $hostport: MSG_CHANNEL_OPEN_FAILURE local_id=${msg.recipientChannel}');

    Channel? chan = channels[msg.recipientChannel!];
    if (chan == null) {
      throw FormatException('$hostport: fail invalid channel');
    }

    handleChannelClose(chan, msg.description);
    channels.remove(msg.recipientChannel);
  }

  /// After receiving this message, the recipient MAY send the given number of bytes
  /// more than it was previously allowed to send; the window size is incremented.
  void handleMSG_CHANNEL_WINDOW_ADJUST(MSG_CHANNEL_WINDOW_ADJUST msg) {
    tracePrint?.call(
        '<- $hostport: MSG_CHANNEL_WINDOW_ADJUST add ${msg.bytesToAdd} to channel ${msg.recipientChannel}');
    Channel? chan = channels[msg.recipientChannel!];
    if (chan == null) {
      throw FormatException('$hostport: window adjust invalid channel');
    }
    chan.windowC += msg.bytesToAdd!;
  }

  /// Data transfer is done with messages of the type SSH_MSG_CHANNEL_DATA.
  void handleMSG_CHANNEL_DATA(MSG_CHANNEL_DATA msg) {
    tracePrint?.call(
        '<- $hostport: MSG_CHANNEL_DATA: channel ${msg.recipientChannel} : ${msg.data!.length} bytes');
    Channel? chan = channels[msg.recipientChannel!];
    if (chan == null) {
      throw FormatException('$hostport: data for invalid channel');
    }
    chan.windowS -= (packetLen - packetMacLen - 4);
    if (chan.windowS < initialWindowSize ~/ 2) {
      writeClearOrEncrypted(
          MSG_CHANNEL_WINDOW_ADJUST(chan.remoteId, initialWindowSize));
      chan.windowS += initialWindowSize;
    }
    handleChannelData(chan, msg.data!);
  }

  /// No explicit response is sent to this message.  However, the application
  /// may send EOF to whatever is at the other end of the channel.
  void handleMSG_CHANNEL_EOF(MSG_CHANNEL_EOF msg) {
    tracePrint?.call('<-$hostport: MSG_CHANNEL_EOF ${msg.recipientChannel}');

    Channel? chan = channels[msg.recipientChannel!];
    if (chan == null) {
      if (print != null) {
        print!('$hostport: close invalid channel');
        return;
      }
    }
    if (!chan!.sentEof) {
      chan.sentEof = true;
      writeCipher(MSG_CHANNEL_EOF(chan.remoteId));
    }
  }

  /// Upon receiving this message, a party MUST send back an SSH_MSG_CHANNEL_CLOSE
  /// unless it has already sent this message for the channel.
  void handleMSG_CHANNEL_CLOSE(MSG_CHANNEL_CLOSE msg) {
    tracePrint?.call('<- $hostport: MSG_CHANNEL_CLOSE ${msg.recipientChannel}');

    Channel? chan = channels[msg.recipientChannel!];
    if (chan == null) {
      if (print != null) {
        print!('$hostport: Close invalid channel');
      }
      return;
    }

    if (!chan.sentClose) {
      chan.sentClose = true;
      if (chan.closed != null) chan.closed!();
      writeCipher(MSG_CHANNEL_CLOSE(chan.remoteId));
      handleChannelClose(chan, 'MSG_CHANNEL_CLOSE');
    }

    channels.remove(msg.recipientChannel);
  }

  /// https://tools.ietf.org/html/rfc4254#section-4
  void handleMSG_GLOBAL_REQUEST(MSG_GLOBAL_REQUEST msg) {
    tracePrint?.call('<- $hostport: MSG_GLOBAL_REQUEST request=${msg.request}');
  }

  /// The recipient MUST NOT accept any data after receiving MSG_DISCONNECT.
  void handleMSG_DISCONNECT(MSG_DISCONNECT msg) {
    tracePrint?.call(
        '<- $hostport: MSG_DISCONNECT ${msg.reasonCode} ${msg.description}');
    if (server!) {
      disconnect('MSG_DISCONNECT ${msg.reasonCode} ${msg.description}');
    }
  }

  /// MSG_IGNORE can be used as an additional protection measure against advanced traffic analysis techniques.
  void handleMSG_IGNORE(MSG_IGNORE msg) {
    tracePrint?.call('<- $hostport: MSG_IGNORE');
  }

  /// All implementations MUST understand MSG_DEBUG, but they are allowed to ignore it.
  void handleMSG_DEBUG(MSG_DEBUG msg) {
    tracePrint?.call('<- $hostport: MSG_DEBUG ${msg.message}');
  }

  /// Computes a new exchange hash [exH] given the server key [kS].
  void updateExchangeHash(Uint8List kS) {
    exH = computeExchangeHash(
      server!,
      kexMethod,
      kexHash!,
      verC,
      verS!,
      kexInitC!,
      kexInitS!,
      kS,
      K!,
      dh,
      ecdh,
      x25519dh,
    );

    /// The exchange hash H from the first key exchange is used as the session identifier.
    if (state == SSHTransportState.FIRST_KEXREPLY) sessionId = exH;

    tracePrint?.call('$hostport: H = "${hex.encode(exH!)}"');
  }

  /// Initializes the block cipher used for encrypted transport.
  BlockCipher initCipher(int cipherId, Uint8List IV, Uint8List key, bool dir) {
    BlockCipher cipher = Cipher.cipher(cipherId);

    tracePrint?.call(
      '$hostport: ${dir ? 'C->S' : 'S->C'} IV  = "${hex.encode(IV)}"',
    );

    tracePrint?.call(
      '$hostport: ${dir ? 'C->S' : 'S->C'} key = "${hex.encode(key)}"',
    );

    cipher.init(
      dir,
      ParametersWithIV(
        KeyParameter(key),
        viewUint8List(IV, 0, cipher.blockSize),
      ),
    );

    return cipher;
  }

  /// Decrypt data using the negotiated block cipher.
  Uint8List readCipher(Uint8List m) => applyBlockCipher(decrypt!, m);

  /// Encrypt Binary Packet data using the negotiated block cipher and MAC.
  void writeCipher(SSHMessage msg) {
    sequenceNumberC2s++;
    final m = msg.toBytes(zwriter, random, encryptBlockSize);
    final encM = applyBlockCipher(encrypt!, m);
    final mac = computeMAC(MAC.mac(macIdC2s), macHashLenC, m,
        sequenceNumberC2s - 1, integrityC2s!, macPrefixC2s);
    socket!.sendRaw(Uint8List.fromList(encM + mac));
    tracePrint?.call('-> $hostport: ${msg}');
  }

  /// Send a Binary Packet (e.g. KEX_INIT) that is initially sent in the clear,
  /// but encryped when keys are being renegotiated.
  void writeClearOrEncrypted(SSHMessage msg) {
    if (state.index > SSHTransportState.FIRST_NEWKEYS.index) {
      return writeCipher(msg);
    }
    sequenceNumberC2s++;
    socket!.sendRaw(msg.toBytes(null, random, encryptBlockSize));
    tracePrint?.call('-> $hostport: ${msg} in clear');
  }

  // Enable the most recently negotiated encryption algorithms.
  void sendNewKeys() {
    writeClearOrEncrypted(MSG_NEWKEYS());
    if (state == SSHTransportState.FIRST_KEXREPLY) {
      state = SSHTransportState.FIRST_NEWKEYS;
    } else {
      state = SSHTransportState.NEWKEYS;
    }
  }

  /// Sends [data] to [channel].
  void sendToChannel(Channel channel, Uint8List data) {
    writeCipher(MSG_CHANNEL_DATA(channel.remoteId, data));
    channel.windowC -= (data.length - 4);
  }

  /// Accepts [MSG_CHANNEL_OPEN] request to open a new [Channel].
  Channel acceptChannel(MSG_CHANNEL_OPEN msg) {
    Channel channel = channels[nextChannelId] = Channel();
    channel.localId = nextChannelId;
    channel.remoteId = msg.senderChannel!;
    channel.windowC = msg.initialWinSize!;
    channel.windowS = initialWindowSize;
    channel.opened = true;
    nextChannelId++;
    return channel;
  }

  /// Send EOF and close for [channel].
  void closeChannel(Channel channel) {
    if (!channel.sentEof) {
      channel.sentEof = true;
      if (socket != null) {
        writeCipher(MSG_CHANNEL_EOF(channel.remoteId));
      }
    }
    if (!channel.sentClose) {
      channel.sentClose = true;
      if (socket != null) {
        writeCipher(MSG_CHANNEL_CLOSE(channel.remoteId));
      }
    }
    channel.cb = null;
    channel.error = null;
    channel.closed = null;
  }

  /// Request remote opens a new TCP channel to [destHost]:[destPort].
  Channel? openTcpChannel(
    String sourceHost,
    int sourcePort,
    String? destHost,
    int? destPort,
    ChannelCallback cb, {
    VoidCallback? connected,
    StringCallback? error,
  }) {
    if (socket == null ||
        state.index <= SSHTransportState.FIRST_NEWKEYS.index) {
      return null;
    }
    debugPrint?.call('openTcpChannel to $destHost:$destPort');
    final chan = channels[nextChannelId] = Channel(
      localId: nextChannelId++,
      windowS: initialWindowSize,
      cb: cb,
      error: error,
      connected: connected,
    );
    nextChannelId++;
    writeCipher(
      MSG_CHANNEL_OPEN_TCPIP(
        'direct-tcpip',
        chan.localId,
        chan.windowS,
        maxPacketSize,
        destHost,
        destPort,
        sourceHost,
        sourcePort,
      ),
    );
    return chan;
  }
}
