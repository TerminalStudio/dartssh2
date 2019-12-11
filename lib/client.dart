// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:math';
import 'dart:convert';
import 'dart:typed_data';

import "package:pointycastle/api.dart";

import 'package:dartssh/agent.dart';
import 'package:dartssh/identity.dart';
import 'package:dartssh/pem.dart';
import 'package:dartssh/protocol.dart';
import 'package:dartssh/serializable.dart';
import 'package:dartssh/socket.dart';
import 'package:dartssh/socket_html.dart'
    if (dart.library.io) 'package:dartssh/socket_io.dart';
import 'package:dartssh/ssh.dart';
import 'package:dartssh/transport.dart';
import 'package:dartssh/websocket_html.dart'
    if (dart.library.io) 'package:dartssh/websocket_io.dart';

/// The Secure Shell (SSH) is a protocol for secure remote login and
/// other secure network services over an insecure network.
class SSHClient extends SSHTransport with SSHAgentForwarding {
  // Parameters
  String login, termvar, startupCommand;
  bool agentForwarding, closeOnDisconnect, startShell;
  FingerprintCallback acceptHostFingerprint;
  Uint8ListFunction getPassword;
  IdentityFunction loadIdentity;
  VoidCallback success;

  // State
  int loginPrompts = 0, passwordPrompts = 0, userauthFail = 0;
  bool acceptedHostkey = false, loadedPw = false, wrotePw = false;
  Uint8List pw;
  int termWidth, termHeight;

  SSHClient(
      {Uri hostport,
      this.login,
      this.termvar = '',
      this.termWidth = 80,
      this.termHeight = 25,
      this.startupCommand,
      bool compress = false,
      this.agentForwarding = false,
      this.closeOnDisconnect,
      this.startShell = true,
      List<Forward> forwardLocal,
      List<Forward> forwardRemote,
      VoidCallback disconnected,
      ResponseCallback response,
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
      socket = (hostport.hasScheme &&
              (hostport.scheme == 'ws' || hostport.scheme == 'wss'))
          ? WebSocketImpl()
          : SocketImpl();

      socket.connect(
          hostport, onConnected, (error) => disconnect('connect error'));
    }
  }

  /// https://tools.ietf.org/html/rfc4253#section-6
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
    if (state != SSHTransportState.FIRST_KEXREPLY &&
        state != SSHTransportState.KEXREPLY) {
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

    if (state == SSHTransportState.FIRST_KEXREPLY) {
      if (acceptHostFingerprint != null) {
        acceptedHostkey = acceptHostFingerprint(hostkeyType, fingerprint);
      } else {
        acceptedHostkey = true;
      }
    }

    sendNewKeys();
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
    initializeDiffieHellmanGroup(msg.p, msg.g, random);
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
      response(this, 'login: ');
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
      response(this, 'Password:');
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
    writeCipher(MSG_CHANNEL_OPEN.create(
        'session', sessionChannel.localId, initialWindowSize, maxPacketSize));
    if (success != null) success();
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
      response(this, msg.instruction);
    }

    for (MapEntry<String, int> prompt in msg.prompts) {
      if (tracePrint != null) {
        tracePrint('$hostport: prompt: ${prompt.key}');
      }
      response(this, prompt.key);
    }

    if (msg.prompts.isNotEmpty) {
      passwordPrompts = msg.prompts.length;
      loadPassword();
    } else {
      writeCipher(MSG_USERAUTH_INFO_RESPONSE(List<Uint8List>()));
    }
  }

  void handleMSG_CHANNEL_REQUEST(MSG_CHANNEL_REQUEST msg) {
    if (tracePrint != null) {
      tracePrint(
          '$hostport: MSG_CHANNEL_REQUEST ${msg.requestType} wantReply=${msg.wantReply}');
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

  void handleChannelOpenConfirmation(Channel chan) {
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
    } else if (chan.connected != null) {
      chan.connected();
    }
  }

  void handleChannelData(Channel chan, Uint8List data) {
    if (chan == sessionChannel) {
      response(this, utf8.decode(data));
    } else if (chan.cb != null) {
      chan.cb(chan, data);
    } else if (chan.agentChannel) {
      handleAgentRead(chan, data);
    }
  }

  void handleChannelClose(Channel chan) {
    if (chan == sessionChannel) {
      writeCipher(MSG_DISCONNECT());
      sessionChannel = null;
    } else if (chan.cb != null) {
      chan.opened = false;
      chan.cb(chan, Uint8List(0));
    }
  }

  bool computeExchangeHashAndVerifyHostKey(Uint8List kS, Uint8List hSig) {
    updateExchangeHash(kS);
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
    response(this, '\r\n');
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
      writeCipher(MSG_USERAUTH_REQUEST(login, 'ssh-connection',
          'keyboard-interactive', '', Uint8List(0), Uint8List(0)));
    } else if (identity.ed25519 != null) {
      Uint8List pubkey = identity.getEd25519PublicKey().toRaw();
      Uint8List challenge = deriveChallenge(sessionId, login, 'ssh-connection',
          'publickey', 'ssh-ed25519', pubkey);
      Ed25519Signature sig = identity.signWithEd25519Key(challenge);
      writeCipher(MSG_USERAUTH_REQUEST(login, 'ssh-connection', 'publickey',
          'ssh-ed25519', pubkey, sig.toRaw()));
    } else if (identity.ecdsaPrivate != null) {
      String keyType = Key.name(identity.ecdsaKeyType);
      Uint8List pubkey = identity.getECDSAPublicKey().toRaw();
      Uint8List challenge = deriveChallenge(
          sessionId, login, 'ssh-connection', 'publickey', keyType, pubkey);
      ECDSASignature sig =
          identity.signWithECDSAKey(challenge, getSecureRandom());
      writeCipher(MSG_USERAUTH_REQUEST(
          login, 'ssh-connection', 'publickey', keyType, pubkey, sig.toRaw()));
    } else if (identity.rsaPrivate != null) {
      Uint8List pubkey = identity.getRSAPublicKey().toRaw();
      Uint8List challenge = deriveChallenge(
          sessionId, login, 'ssh-connection', 'publickey', 'ssh-rsa', pubkey);
      RSASignature sig = identity.signWithRSAKey(challenge);
      writeCipher(MSG_USERAUTH_REQUEST(login, 'ssh-connection', 'publickey',
          'ssh-rsa', pubkey, sig.toRaw()));
    }
  }

  @override
  void sendChannelData(Uint8List b) {
    if (loginPrompts != 0) {
      response(this, utf8.decode(b));
      bool cr = b.isNotEmpty && b.last == '\n'.codeUnits[0];
      login += String.fromCharCodes(b, 0, b.length - (cr ? 1 : 0));
      if (cr) {
        response(this, '\n');
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

  void setTerminalWindowSize(int w, int h) {
    termWidth = w;
    termHeight = h;
    if (socket == null || sessionChannel == null) return;
    writeCipher(MSG_CHANNEL_REQUEST.ptyReq(
        sessionChannel.remoteId,
        'window-change',
        Point(termWidth, termHeight),
        Point(termWidth * 8, termHeight * 12),
        termvar,
        '',
        false));
  }

  void exec(String command, {bool wantReply = true}) {
    assert(socket != null && sessionChannel != null);
    if (socket == null || sessionChannel == null) return;
    writeCipher(MSG_CHANNEL_REQUEST.exec(
        sessionChannel.remoteId, 'exec', command, wantReply));
  }
}

/// Implement same [SocketInterface] as actual [Socket] but over [SSHClient] tunnel.
class SSHTunneledSocketImpl extends SocketInterface {
  SSHClient client;
  Identity identity;
  Channel channel;
  String tunnelToHost;
  int tunnelToPort;
  Function connected, connectError, onError, onDone, onMessage;

  SSHTunneledSocketImpl(Uri url, String login, String key, String password,
      {StringCallback print, StringCallback debugPrint}) {
    identity = key == null ? null : parsePem(key);
    client = SSHClient(
        socketInput: SocketImpl(),
        hostport: url,
        login: login,
        getPassword: password == null ? null : () => utf8.encode(password),
        loadIdentity: () => identity,
        response: (_, m) {},
        disconnected: () {
          if (onDone != null) onDone(null);
        },
        startShell: false,
        success: () {
          channel = client.openTcpChannel('127.0.0.1', 1234, tunnelToHost,
              tunnelToPort, (_, Uint8List m) => onMessage(m), () {
            if (connected != null) connected(client.socket);
            connected = connectError = null;
          });
        },
        print: print,
        debugPrint: debugPrint);
  }

  @override
  void close() => client.disconnect('close');

  @override
  void handleError(Function errorHandler) => onError = errorHandler;

  @override
  void handleDone(Function doneHandler) => onDone = doneHandler;

  @override
  void listen(Function messageHandler) => onMessage = messageHandler;

  @override
  void connect(Uri address, Function connectHandler, Function errorHandler,
      {int timeoutSeconds = 15, bool ignoreBadCert = false}) {
    tunnelToHost = address.host;
    tunnelToPort = address.port;
    connected = connectHandler;
    connectError = errorHandler;
    client.socket.connect(client.hostport, client.onConnected, (error) {
      client.disconnect('connect error');
      if (connectError != null) connectError(error);
    });
  }

  @override
  void send(String text) => sendRaw(Uint8List.fromList(text.codeUnits));

  @override
  void sendRaw(Uint8List raw) => client.sendToChannel(channel, raw);
}
