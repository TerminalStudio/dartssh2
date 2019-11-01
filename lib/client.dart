// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:math';
import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import "package:pointycastle/api.dart";

import 'package:dartssh/agent.dart';
import 'package:dartssh/identity.dart';
import 'package:dartssh/kex.dart';
import 'package:dartssh/protocol.dart';
import 'package:dartssh/serializable.dart';
import 'package:dartssh/socket.dart';
import 'package:dartssh/socket_html.dart'
    if (dart.library.io) 'package:dartssh/socket_io.dart';
import 'package:dartssh/ssh.dart';
import 'package:dartssh/transport.dart';

/// The Secure Shell (SSH) is a protocol for secure remote login and
/// other secure network services over an insecure network.
class SSHClient extends SSHTransport {
  String login, termvar, startupCommand;
  bool agentForwarding, closeOnDisconnect, startShell;
  FingerprintCallback acceptHostFingerprint;
  Uint8ListFunction getPassword;
  IdentityFunction loadIdentity;
  VoidCallback success;

  int loginPrompts = 0, passwordPrompts = 0, userauthFail = 0;
  bool acceptedHostkey = false, loadedPw = false, wrotePw = false;
  Uint8List pw;
  Identity identity;
  Channel sessionChannel;
  int termWidth = 80, termHeight = 25;

  SSHClient(
      {String hostport,
      this.login,
      this.termvar = '',
      this.startupCommand,
      bool compress = false,
      this.agentForwarding = false,
      this.closeOnDisconnect,
      this.startShell = true,
      List<Forward> forwardLocal,
      List<Forward> forwardRemote,
      VoidCallback disconnected,
      StringCallback response,
      StringCallback print,
      StringCallback debugPrint,
      StringCallback tracePrint,
      this.success,
      this.acceptHostFingerprint,
      this.loadIdentity,
      this.getPassword,
      SocketInterface socketInput,
      Random random,
      SecureRandom secureRandom})
      : super(false,
            hostport: hostport,
            compress: compress,
            forwardLocal: forwardLocal,
            forwardRemote: forwardRemote,
            disconnected: disconnected,
            response: response,
            print: print,
            debugPrint: debugPrint,
            tracePrint: tracePrint,
            socket: socketInput,
            random: random,
            secureRandom: secureRandom) {
    if (socket == null) {
      if (debugPrint != null) {
        debugPrint('Connecting to $hostport');
      }
      socket = SocketImpl();
      socket.connect(
          hostport, onConnected, (error) => disconnect('connect error'));
    }
  }

  void handleAgentRead(Channel channel, Uint8List msg) {
    channel.buf.add(msg);
    while (channel.buf.data.length > 4) {
      SerializableInput input = SerializableInput(channel.buf.data);
      int agentPacketLen = input.getUint32();
      if (input.remaining < agentPacketLen) break;
      handleAgentPacket(channel,
          SerializableInput(input.viewOffset(input.offset, agentPacketLen)));
      channel.buf.flush(agentPacketLen + 4);
    }
  }

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

  /// https://tools.ietf.org/html/rfc4253#section-6
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

      case MSG_KEXDH_REPLY.ID:
      case MSG_KEX_DH_GEX_REPLY.ID:
        handleMSG_KEXDH_REPLY(packetId, packet);
        break;

      case MSG_NEWKEYS.ID:
        handleMSG_NEWKEYS();
        writeCipher(MSG_SERVICE_REQUEST('ssh-userauth'));
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
        handleMSG_CHANNEL_OPEN(
            MSG_CHANNEL_OPEN()..deserialize(packetS), packetS);
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

  @override
  void sendDiffileHellmanInit() {
    initializeDiffieHellman(kexMethod, random);
    if (KEX.x25519DiffieHellman(kexMethod)) {
      writeClearOrEncrypted(MSG_KEX_ECDH_INIT(x25519dh.myPubKey));
    } else if (KEX.ellipticCurveDiffieHellman(kexMethod)) {
      writeClearOrEncrypted(MSG_KEX_ECDH_INIT(ecdh.cText));
    } else if (KEX.diffieHellmanGroupExchange(kexMethod)) {
      writeClearOrEncrypted(
          MSG_KEX_DH_GEX_REQUEST(dh.gexMin, dh.gexMax, dh.gexPref));
    } else if (KEX.diffieHellman(kexMethod)) {
      writeClearOrEncrypted(MSG_KEXDH_INIT(dh.e));
    } else {
      throw FormatException('$hostport: unknown kex method: $kexMethod');
    }
  }

  /// https://tools.ietf.org/html/rfc4253#section-8
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
      if (acceptHostFingerprint != null) {
        acceptedHostkey = acceptHostFingerprint(hostkeyType, fingerprint);
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

    K = x25519dh.computeSecret(msg.qS);
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

  void handleMSG_SERVICE_ACCEPT() {
    if (tracePrint != null) tracePrint('$hostport: MSG_SERVICE_ACCEPT');
    if (login == null || login.isEmpty) {
      loginPrompts = 1;
      response('login: ');
    }
    if (identity == null && loadIdentity != null) {
      identity = loadIdentity();
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

  void handleMSG_CHANNEL_OPEN(MSG_CHANNEL_OPEN msg, SerializableInput packetS) {
    if (tracePrint != null) {
      tracePrint('$hostport: MSG_CHANNEL_OPEN type=${msg.channelType}');
    }
    if (msg.channelType == 'auth-agent@openssh.com' && agentForwarding) {
      Channel channel = acceptChannel(msg);
      channel.agentChannel = true;
      writeCipher(MSG_CHANNEL_OPEN_CONFIRMATION(
          channel.remoteId, channel.localId, channel.windowS, maxPacketSize));
    } else if (msg.channelType == 'forwarded-tcpip') {
      MSG_CHANNEL_OPEN_TCPIP openTcpIp = MSG_CHANNEL_OPEN_TCPIP()
        ..deserialize(packetS);
      Forward forward =
          forwardingRemote == null ? null : forwardingRemote[openTcpIp.dstPort];
      if (forward == null || remoteForward == null) {
        if (print != null) {
          print('unknown port open ${openTcpIp.dstPort}');
        }
        writeCipher(MSG_CHANNEL_OPEN_FAILURE(msg.senderChannel, 0, '', ''));
      } else {
        Channel channel = acceptChannel(msg);
        remoteForward(channel, forward.targetHost, forward.targetPort,
            openTcpIp.srcHost, openTcpIp.srcPort);
        writeCipher(MSG_CHANNEL_OPEN_CONFIRMATION(
            channel.remoteId, channel.localId, channel.windowS, maxPacketSize));
      }
    } else {
      if (print != null) {
        print('unknown channel open ${msg.channelType}');
      }
      writeCipher(MSG_CHANNEL_OPEN_FAILURE(msg.senderChannel, 0, '', ''));
    }
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
      handleAgentRead(chan, msg.data);
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

  void handleAGENTC_REQUEST_IDENTITIES(Channel channel) {
    if (tracePrint != null) {
      tracePrint('$hostport: agent channel: AGENTC_REQUEST_IDENTITIES');
    }
    AGENT_IDENTITIES_ANSWER reply = AGENT_IDENTITIES_ANSWER();
    if (identity != null) {
      if (identity.ed25519 != null) {
        reply.keys.add(MapEntry<Uint8List, String>(
            identity.getEd25519PublicKey().toRaw(), ''));
      }
      if (identity.ecdsaPublic != null) {
        reply.keys.add(MapEntry<Uint8List, String>(
            identity.getECDSAPublicKey().toRaw(), ''));
      }
      if (identity.rsaPublic != null) {
        reply.keys.add(MapEntry<Uint8List, String>(
            identity.getRSAPublicKey().toRaw(), ''));
      }
    }
    sendToChannel(channel, reply.toRaw());
  }

  void handleAGENTC_SIGN_REQUEST(Channel channel, AGENTC_SIGN_REQUEST msg) {
    if (tracePrint != null) {
      tracePrint('$hostport: agent channel: AGENTC_SIGN_REQUEST');
    }
    SerializableInput keyStream = SerializableInput(msg.key);
    String keyType = deserializeString(keyStream);
    Uint8List sig;

    if (keyType == Key.name(Key.ED25519)) {
      sig = identity.signWithEd25519Key(msg.data).toRaw();
    } else if (keyType == Key.name(Key.ECDSA_SHA2_NISTP256) ||
        keyType == Key.name(Key.ECDSA_SHA2_NISTP384) ||
        keyType == Key.name(Key.ECDSA_SHA2_NISTP521)) {
      sig = identity.signWithECDSAKey(msg.data, getSecureRandom()).toRaw();
    } else if (keyType == Key.name(Key.RSA)) {
      sig = identity.signWithRSAKey(msg.data).toRaw();
    }

    if (sig != null) {
      sendToChannel(channel, AGENT_SIGN_RESPONSE(sig).toRaw());
    } else {
      sendToChannel(channel, AGENT_FAILURE().toRaw());
    }
  }

  bool computeExchangeHashAndVerifyHostKey(Uint8List kS, Uint8List hSig) {
    computeTheExchangeHash(kS);
    return verifyHostKey(exH, hostkeyType, kS, hSig);
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
    } else if (identity.ed25519 != null) {
      Uint8List pubkey = identity.getEd25519PublicKey().toRaw();
      Uint8List challenge = deriveChallenge(sessionId, login, 'ssh-connection',
          'publickey', 'ssh-ed25519', pubkey);
      Ed25519Signature sig = identity.signWithEd25519Key(challenge);
      writeCipher(MSG_USERAUTH_REQUEST(login, 'ssh-connection', 'publickey',
          'ssh-ed25519', pubkey, sig.toRaw()));
      return;
    } else if (identity.ecdsaPrivate != null) {
      String keyType = Key.name(identity.ecdsaKeyType);
      Uint8List pubkey = identity.getECDSAPublicKey().toRaw();
      Uint8List challenge = deriveChallenge(
          sessionId, login, 'ssh-connection', 'publickey', keyType, pubkey);
      ECDSASignature sig =
          identity.signWithECDSAKey(challenge, getSecureRandom());
      writeCipher(MSG_USERAUTH_REQUEST(
          login, 'ssh-connection', 'publickey', keyType, pubkey, sig.toRaw()));
      return;
    } else if (identity.rsaPrivate != null) {
      Uint8List pubkey = identity.getRSAPublicKey().toRaw();
      Uint8List challenge = deriveChallenge(
          sessionId, login, 'ssh-connection', 'publickey', 'ssh-rsa', pubkey);
      RSASignature sig = identity.signWithRSAKey(challenge);
      writeCipher(MSG_USERAUTH_REQUEST(login, 'ssh-connection', 'publickey',
          'ssh-rsa', pubkey, sig.toRaw()));
      return;
    }
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

  Channel acceptChannel(MSG_CHANNEL_OPEN msg) {
    Channel channel = channels[nextChannelId];
    channel.localId = nextChannelId;
    channel.remoteId = msg.senderChannel;
    channel.windowC = msg.initialWinSize;
    channel.windowS = initialWindowSize;
    channel.opened = true;
    nextChannelId++;
    return channel;
  }
}
