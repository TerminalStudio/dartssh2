// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

// ignore_for_file: non_constant_identifier_names

import 'dart:math';
import 'dart:convert';
import 'dart:typed_data';

import "package:pointycastle/api.dart";

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/agent.dart';
import 'package:dartssh2/src/identity.dart';
import 'package:dartssh2/src/pem.dart';
import 'package:dartssh2/src/protocol.dart';
import 'package:dartssh2/src/serializable.dart';
import 'package:dartssh2/src/socket.dart';
import 'package:dartssh2/src/ssh.dart';
import 'package:dartssh2/src/transport.dart';

/// The Secure Shell (SSH) is a protocol for secure remote login and
/// other secure network services over an insecure network.
class SSHClient extends SSHTransport with SSHAgentForwarding {
  // Parameters
  bool? agentForwarding, closeOnDisconnect;
  FingerprintCallback? acceptHostFingerprint;
  Uint8ListFunction? getPassword;
  IdentityFunction? loadIdentity;
  List<VoidCallback> success = <VoidCallback>[];

  // State
  int loginPrompts = 0, passwordPrompts = 0, userauthFail = 0;
  bool acceptedHostkey = false, loadedPw = false, wrotePw = false;
  Uint8List? pw;

  /// width of the terminal window in characters
  int termWidth;

  /// height of the terminal window in characters
  int termHeight;

  /// The username to authenticate as.
  String login;

  /// Whether to start an interactive shell session on the SSH server after the
  /// connection is established. Default is true.
  final bool startShell;

  /// TERM environment variable value (e.g., vt100, xterm). 'xterm' by default.
  /// Use `Platform.environment['TERM']` if you want to use the value of your
  /// shell or `xterm-256color` for better color support.
  final String termvar;

  SSHClient({
    Uri? hostport,
    required this.login,
    this.termvar = 'xterm',
    this.termWidth = 80,
    this.termHeight = 25,
    bool compress = false,
    this.agentForwarding = false,
    this.closeOnDisconnect,
    this.startShell = true,
    List<Forward>? forwardLocal,
    List<Forward>? forwardRemote,
    VoidCallback? disconnected,
    ResponseCallback? response,
    StringCallback? print,
    StringCallback? debugPrint,
    StringCallback? tracePrint,
    VoidCallback? success,
    this.acceptHostFingerprint,
    this.loadIdentity,
    this.getPassword,
    SocketInterface? socketInput,
    Random? random,
    SecureRandom? secureRandom,
  }) : super(
          false,
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
          secureRandom: secureRandom,
        ) {
    if (success != null) {
      this.success.add(success);
    }
    if (socket == null) {
      debugPrint?.call('Connecting to $hostport');

      socket = (hostport!.hasScheme &&
              (hostport.scheme == 'ws' || hostport.scheme == 'wss'))
          ? WebSocketImpl()
          : SocketImpl();

      socket!.connect(
        hostport,
        onConnected,
        (error) => disconnect('connect error'),
      );
    }
  }

  void responseText(String text) {
    response?.call(Uint8List.fromList(text.codeUnits));
  }

  /// https://tools.ietf.org/html/rfc4253#section-6
  @override
  void handlePacket(Uint8List packet) {
    packetId = packetS!.getUint8();
    switch (packetId) {
      case MSG_KEXINIT.ID:
        state = state == SSHTransportState.FIRST_KEXINIT
            ? SSHTransportState.FIRST_KEXREPLY
            : SSHTransportState.KEXREPLY;
        handleMSG_KEXINIT(MSG_KEXINIT()..deserialize(packetS!), packet);
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
            MSG_USERAUTH_FAILURE()..deserialize(packetS!));
        break;

      case MSG_USERAUTH_SUCCESS.ID:
        handleMSG_USERAUTH_SUCCESS();
        break;

      case MSG_USERAUTH_INFO_REQUEST.ID:
        handleMSG_USERAUTH_INFO_REQUEST(
            MSG_USERAUTH_INFO_REQUEST()..deserialize(packetS!));
        break;

      case MSG_GLOBAL_REQUEST.ID:
        handleMSG_GLOBAL_REQUEST(MSG_GLOBAL_REQUEST()..deserialize(packetS!));
        break;

      case MSG_CHANNEL_OPEN.ID:
        handleMSG_CHANNEL_OPEN(
            MSG_CHANNEL_OPEN()..deserialize(packetS!), packetS);
        break;

      case MSG_CHANNEL_OPEN_CONFIRMATION.ID:
        handleMSG_CHANNEL_OPEN_CONFIRMATION(
            MSG_CHANNEL_OPEN_CONFIRMATION()..deserialize(packetS!));
        break;

      case MSG_CHANNEL_OPEN_FAILURE.ID:
        handleMSG_CHANNEL_OPEN_FAILURE(
            MSG_CHANNEL_OPEN_FAILURE()..deserialize(packetS!));
        break;

      case MSG_CHANNEL_WINDOW_ADJUST.ID:
        handleMSG_CHANNEL_WINDOW_ADJUST(
            MSG_CHANNEL_WINDOW_ADJUST()..deserialize(packetS!));
        break;

      case MSG_CHANNEL_DATA.ID:
        handleMSG_CHANNEL_DATA(MSG_CHANNEL_DATA()..deserialize(packetS!));
        break;

      case MSG_CHANNEL_EOF.ID:
        handleMSG_CHANNEL_EOF(MSG_CHANNEL_EOF()..deserialize(packetS!));
        break;

      case MSG_CHANNEL_CLOSE.ID:
        handleMSG_CHANNEL_CLOSE(MSG_CHANNEL_CLOSE()..deserialize(packetS!));
        break;

      case MSG_CHANNEL_REQUEST.ID:
        handleMSG_CHANNEL_REQUEST(MSG_CHANNEL_REQUEST()..deserialize(packetS!));
        break;

      case MSG_CHANNEL_SUCCESS.ID:
        tracePrint?.call('$hostport: MSG_CHANNEL_SUCCESS');
        break;

      case MSG_CHANNEL_FAILURE.ID:
        tracePrint?.call('$hostport: MSG_CHANNEL_FAILURE');
        break;

      case MSG_DISCONNECT.ID:
        handleMSG_DISCONNECT(MSG_DISCONNECT()..deserialize(packetS!));
        break;

      case MSG_IGNORE.ID:
        handleMSG_IGNORE(MSG_IGNORE()..deserialize(packetS!));
        break;

      case MSG_DEBUG.ID:
        handleMSG_DEBUG(MSG_DEBUG()..deserialize(packetS!));
        break;

      default:
        this.print?.call(
            '$hostport: unknown packet number: $packetId, len $packetLen');
        break;
    }
  }

  /// Initialize a shared-secret negotiation culminating with [MSG_NEWKEYS].
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
      throw StateError('$hostport: unexpected state $state');
    }

    if (guessedS! && !guessedRightS!) {
      guessedS = false;
      this.print?.call('$hostport: server guessed wrong, ignoring packet');
      return;
    }

    Uint8List? fingerprint;

    if (packetId == MSG_KEX_ECDH_REPLY.ID &&
        KEX.x25519DiffieHellman(kexMethod)) {
      fingerprint = handleX25519MSG_KEX_ECDH_REPLY(
              MSG_KEX_ECDH_REPLY()..deserialize(packetS!)) ??
          fingerprint;
    } else if (packetId == MSG_KEXDH_REPLY.ID &&
        KEX.ellipticCurveDiffieHellman(kexMethod)) {
      fingerprint = handleEcDhMSG_KEX_ECDH_REPLY(
              MSG_KEX_ECDH_REPLY()..deserialize(packetS!)) ??
          fingerprint;
    } else if (packetId == MSG_KEXDH_REPLY.ID &&
        KEX.diffieHellmanGroupExchange(kexMethod)) {
      handleDhGroupMSG_KEX_DH_GEX_GROUP(
          MSG_KEX_DH_GEX_GROUP()..deserialize(packetS!));
      return;
    } else {
      fingerprint =
          handleDhMSG_KEXDH_REPLY(MSG_KEXDH_REPLY()..deserialize(packetS!)) ??
              fingerprint;
    }

    if (state == SSHTransportState.FIRST_KEXREPLY) {
      if (acceptHostFingerprint != null) {
        acceptedHostkey = acceptHostFingerprint!(hostkeyType, fingerprint);
      } else {
        acceptedHostkey = true;
      }
    }

    sendNewKeys();
  }

  /// Completes X25519 key exchange.
  Uint8List? handleX25519MSG_KEX_ECDH_REPLY(MSG_KEX_ECDH_REPLY msg) {
    tracePrint?.call('<- $hostport: MSG_KEX_ECDH_REPLY for X25519DH');

    Uint8List? fingerprint;

    if (!acceptedHostkey) fingerprint = msg.kS;

    K = x25519dh.computeSecret(msg.qS!);
    if (!computeExchangeHashAndVerifyHostKey(msg.kS!, msg.hSig)) {
      throw FormatException('$hostport: verify hostkey failed');
    }

    return fingerprint;
  }

  /// Completes Elliptic-curve Diffie–Hellman key exchange.
  Uint8List? handleEcDhMSG_KEX_ECDH_REPLY(MSG_KEX_ECDH_REPLY msg) {
    tracePrint?.call('<- $hostport: MSG_KEX_ECDH_REPLY for ECDH');

    Uint8List? fingerprint;
    if (!acceptedHostkey) fingerprint = msg.kS;

    K = ecdh.computeSecret(msg.qS!);
    if (!computeExchangeHashAndVerifyHostKey(msg.kS!, msg.hSig)) {
      throw FormatException('$hostport: verify hostkey failed');
    }

    return fingerprint;
  }

  /// Completes Diffie-Hellman Group Exchange and begins key exchange.
  void handleDhGroupMSG_KEX_DH_GEX_GROUP(MSG_KEX_DH_GEX_GROUP msg) {
    tracePrint?.call('<- $hostport: MSG_KEX_DH_GEX_GROUP');

    initializeDiffieHellmanGroup(msg.p!, msg.g!, random);
    writeClearOrEncrypted(MSG_KEX_DH_GEX_INIT(dh.e));
  }

  /// Completes Diffie-Hellman key exchange.
  Uint8List? handleDhMSG_KEXDH_REPLY(MSG_KEXDH_REPLY msg) {
    tracePrint?.call('<- $hostport: MSG_KEXDH_REPLY');

    Uint8List? fingerprint;

    if (!acceptedHostkey) fingerprint = msg.kS;

    K = dh.computeSecret(msg.f);
    if (!computeExchangeHashAndVerifyHostKey(msg.kS!, msg.hSig)) {
      throw FormatException('$hostport: verify hostkey failed');
    }

    return fingerprint;
  }

  /// Handle accepted [MSG_SERVICE_REQUEST] sent in response to [MSG_NEWKEYS].
  void handleMSG_SERVICE_ACCEPT() {
    tracePrint?.call('<- $hostport: MSG_SERVICE_ACCEPT');
    if (login.isEmpty) {
      loginPrompts = 1;
      responseText('login: ');
    }
    if (identity == null && loadIdentity != null) {
      identity = loadIdentity!();
    }
    sendAuthenticationRequest();
  }

  /// If key authentication failed, then try password authentication.
  void handleMSG_USERAUTH_FAILURE(MSG_USERAUTH_FAILURE msg) {
    tracePrint?.call(
        '<- $hostport: MSG_USERAUTH_FAILURE: auth_left="${msg.authLeft}" loadedPw=$loadedPw useauthFail=$userauthFail');

    if (!loadedPw) clearPassword();
    userauthFail++;
    if (userauthFail == 1 && !wrotePw) {
      responseText('Password:');
      passwordPrompts = 1;
      getThenSendPassword();
    } else {
      throw FormatException('$hostport: authorization failed');
    }
  }

  /// After successfull authentication, open the session channel and start compression.
  void handleMSG_USERAUTH_SUCCESS() {
    tracePrint?.call('<- $hostport: MSG_USERAUTH_SUCCESS');

    sessionChannel =
        SSHChannel(localId: nextChannelId, windowS: initialWindowSize);
    channels[nextChannelId] = sessionChannel!;
    nextChannelId++;

    if (compressIdC2s == Compression.OpenSSHZLib) {
      // zwriter = ArchiveDeflateWriter();
      throw FormatException('compression not supported');
    }
    if (compressIdS2c == Compression.OpenSSHZLib) {
      // zreader = ArchiveInflateReader();
      throw FormatException('compression not supported');
    }
    writeCipher(MSG_CHANNEL_OPEN(
        'session', sessionChannel!.localId, initialWindowSize, maxPacketSize));
    for (VoidCallback successCallback in success) {
      successCallback();
    }
  }

  /// The server can optionally request authentication information from the client.
  void handleMSG_USERAUTH_INFO_REQUEST(MSG_USERAUTH_INFO_REQUEST msg) {
    tracePrint?.call(
        '<- $hostport: MSG_USERAUTH_INFO_REQUEST prompts=${msg.prompts.length}');
    if (msg.instruction.isNotEmpty) {
      tracePrint?.call('$hostport: instruction: ${msg.instruction}');
      responseText(msg.instruction);
    }

    for (MapEntry<String, int> prompt in msg.prompts) {
      tracePrint?.call('$hostport: prompt: ${prompt.key}');
      responseText(prompt.key);
    }

    if (msg.prompts.isNotEmpty) {
      passwordPrompts = msg.prompts.length;
      getThenSendPassword();
    } else {
      writeCipher(MSG_USERAUTH_INFO_RESPONSE(<Uint8List>[]));
    }
  }

  /// Logs any (unhandled) channel specific requests from server.
  void handleMSG_CHANNEL_REQUEST(MSG_CHANNEL_REQUEST msg) {
    tracePrint?.call(
        '<- $hostport: MSG_CHANNEL_REQUEST ${msg.requestType} wantReply=${msg.wantReply}');
  }

  /// Handles server-initiated [SSHChannel] to client.  e.g. for remote port forwarding,
  /// or SSH agent request.
  void handleMSG_CHANNEL_OPEN(
    MSG_CHANNEL_OPEN msg,
    SerializableInput? packetS,
  ) {
    tracePrint?.call('<- $hostport: MSG_CHANNEL_OPEN type=${msg.channelType}');
    if (msg.channelType == 'auth-agent@openssh.com' && agentForwarding!) {
      SSHChannel channel = acceptChannel(msg);
      channel.agentChannel = true;
      writeCipher(MSG_CHANNEL_OPEN_CONFIRMATION(
          channel.remoteId, channel.localId, channel.windowS, maxPacketSize));
    } else if (msg.channelType == 'forwarded-tcpip') {
      MSG_CHANNEL_OPEN_TCPIP openTcpIp = MSG_CHANNEL_OPEN_TCPIP()
        ..deserialize(packetS!);
      Forward? forward = forwardingRemote == null
          ? null
          : forwardingRemote![openTcpIp.dstPort];
      if (forward == null || remoteForward == null) {
        this.print?.call('unknown port open ${openTcpIp.dstPort}');
        writeCipher(MSG_CHANNEL_OPEN_FAILURE(msg.senderChannel, 0, '', ''));
      } else {
        SSHChannel channel = acceptChannel(msg);
        remoteForward!(channel, forward.targetHost, forward.targetPort,
            openTcpIp.srcHost, openTcpIp.srcPort);
        writeCipher(MSG_CHANNEL_OPEN_CONFIRMATION(
            channel.remoteId, channel.localId, channel.windowS, maxPacketSize));
      }
    } else {
      this.print?.call('unknown channel open ${msg.channelType}');
      writeCipher(MSG_CHANNEL_OPEN_FAILURE(msg.senderChannel, 0, '', ''));
    }
  }

  /// Handles successfully opened client-initiated [SSHChannel].
  @override
  void handleChannelOpenConfirmation(SSHChannel channel) {
    if (channel == sessionChannel) {
      handleSessionStarted();
    } else if (channel.connected != null) {
      channel.connected?.call();
    }
  }

  /// After the session is established, initialize channel state.
  void handleSessionStarted() {
    if (agentForwarding!) {
      writeCipher(
        MSG_CHANNEL_REQUEST.exec(
          sessionChannel!.remoteId,
          'auth-agent-req@openssh.com',
          '',
          true,
        ),
      );
    }

    if (forwardRemote != null) {
      for (Forward forward in forwardRemote!) {
        writeCipher(MSG_GLOBAL_REQUEST_TCPIP('', forward.port));
        forwardingRemote![forward.port] = forward;
      }
    }

    if (startShell) {
      writeCipher(
        MSG_CHANNEL_REQUEST.ptyReq(
          sessionChannel!.remoteId,
          'pty-req',
          Point(termWidth, termHeight),
          Point(termWidth * 8, termHeight * 12),
          termvar,
          '',
          true,
        ),
      );

      writeCipher(
        MSG_CHANNEL_REQUEST.exec(
          sessionChannel!.remoteId,
          'shell',
          '',
          true,
        ),
      );
    }
  }

  /// Handles all [SSHChannel] data for this session.
  @override
  void handleChannelData(SSHChannel chan, Uint8List data) {
    if (chan == sessionChannel) {
      response?.call(data);
    } else if (chan.cb != null) {
      chan.cb!(data);
    } else if (chan.agentChannel) {
      handleAgentRead(chan, data);
    }
  }

  /// Handles [SSHChannel] closed by server.
  @override
  void handleChannelClose(SSHChannel chan, [String? description]) {
    if (chan == sessionChannel) {
      writeCipher(MSG_DISCONNECT());
      sessionChannel = null;
    } else if (chan.cb != null) {
      chan.opened = false;
      if (chan.error != null) {
        chan.error!(description);
      } else {
        chan.cb!(Uint8List(0));
      }
    }
  }

  /// Updates [exH] and verifies [kS]'s [hSig].  On success [MSG_NEWKEYS] is sent.
  /// https://datatracker.ietf.org/doc/html/rfc4253#section-8
  bool computeExchangeHashAndVerifyHostKey(Uint8List kS, Uint8List? hSig) {
    updateExchangeHash(kS);
    return verifyHostKey(exH, hostkeyType, kS, hSig);
  }

  /// Calls [sendPassword()] if [getPassword] succeeds.
  void getThenSendPassword() {
    if (getPassword != null && (pw = getPassword!()) != null) sendPassword();
  }

  /// "Securely" clears the local password storage.
  void clearPassword() {
    if (pw == null) return;
    for (int i = 0; i < pw!.length; i++) {
      pw![i] ^= random.nextInt(255);
    }
    pw = null;
  }

  /// Sends [MSG_USERAUTH_REQUEST] with password [pw].
  void sendPassword() {
    responseText('\r\n');
    wrotePw = true;
    if (userauthFail != 0) {
      writeCipher(MSG_USERAUTH_REQUEST(
          login, 'ssh-connection', 'password', '', pw, Uint8List(0)));
    } else {
      List<Uint8List?> prompt =
          List<Uint8List?>.filled(passwordPrompts, Uint8List(0));
      prompt.last = pw;
      writeCipher(MSG_USERAUTH_INFO_RESPONSE(prompt));
    }
    passwordPrompts = 0;
    clearPassword();
  }

  /// Sends [MSG_USERAUTH_REQUEST] optionally using [identity] or keyboard-interactive.
  void sendAuthenticationRequest() {
    final identity = this.identity;
    if (identity == null) {
      debugPrint?.call('$hostport: Keyboard interactive');
      writeCipher(
        MSG_USERAUTH_REQUEST(
          login,
          'ssh-connection',
          'keyboard-interactive',
          '',
          Uint8List(0),
          Uint8List(0),
        ),
      );
    } else if (identity.ed25519 != null) {
      debugPrint?.call('$hostport: Sending Ed25519 authorization request');
      final pubkey = identity.getEd25519PublicKey().toRaw();
      final challenge = deriveChallenge(
        sessionId!,
        login,
        'ssh-connection',
        'publickey',
        'ssh-ed25519',
        pubkey,
      );
      final sig = identity.signWithEd25519Key(challenge);
      writeCipher(
        MSG_USERAUTH_REQUEST(
          login,
          'ssh-connection',
          'publickey',
          'ssh-ed25519',
          pubkey,
          sig.toRaw(),
        ),
      );
    } else if (identity.ecdsaPrivate != null) {
      debugPrint?.call('$hostport: Sending ECDSA authorization request');
      final keyType = Key.name(identity.ecdsaKeyType);
      final pubkey = identity.getECDSAPublicKey().toRaw();
      final challenge = deriveChallenge(
        sessionId!,
        login,
        'ssh-connection',
        'publickey',
        keyType,
        pubkey,
      );
      final sig = identity.signWithECDSAKey(challenge, getSecureRandom());
      writeCipher(
        MSG_USERAUTH_REQUEST(
          login,
          'ssh-connection',
          'publickey',
          keyType,
          pubkey,
          sig.toRaw(),
        ),
      );
    } else if (identity.rsaPrivate != null) {
      debugPrint?.call('$hostport: Sending RSA authorization request');
      final pubkey = identity.getRSAPublicKey().toRaw();
      final challenge = deriveChallenge(
        sessionId!,
        login,
        'ssh-connection',
        'publickey',
        'ssh-rsa',
        pubkey,
      );
      final sig = identity.signWithRSAKey(challenge);
      writeCipher(
        MSG_USERAUTH_REQUEST(
          login,
          'ssh-connection',
          'publickey',
          'ssh-rsa',
          pubkey,
          sig.toRaw(),
        ),
      );
    }
  }

  /// Sends channel data [b] on [sessionChannel].
  /// Optionally [b] is captured by [loginPrompts] or [passwordPrompts].
  @override
  void sendChannelData(Uint8List b) {
    if (loginPrompts != 0) {
      response?.call(b);
      bool cr = b.isNotEmpty && b.last == '\n'.codeUnits[0];
      login = login + String.fromCharCodes(b, 0, b.length - (cr ? 1 : 0));
      if (cr) {
        responseText('\n');
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
        sendToChannel(sessionChannel!, b);
      }
    }
  }

  /// Sends window-change [MSG_CHANNEL_REQUEST].
  void setTerminalWindowSize(int w, int h) {
    termWidth = w;
    termHeight = h;
    if (socket == null || sessionChannel == null) return;
    writeCipher(
      MSG_CHANNEL_REQUEST.ptyReq(
        sessionChannel!.remoteId,
        'window-change',
        Point(termWidth, termHeight),
        Point(termWidth * 8, termHeight * 12),
        termvar,
        '',
        false,
      ),
    );
  }

  void exec(String command, {bool wantReply = true}) {
    assert(socket != null && sessionChannel != null);
    if (socket == null || sessionChannel == null) return;
    writeCipher(MSG_CHANNEL_REQUEST.exec(
        sessionChannel!.remoteId, 'exec', command, wantReply));
  }
}

/// Implement same [SocketInterface] as actual [Socket] but over [SSHClient] tunnel.
class SSHTunneledSocketImpl extends SocketInterface {
  bool clientOwner, shutdownSend = false, shutdownRecv = false;
  late SSHClient client;
  SSHIdentity? identity;
  SSHChannel? channel;
  String? sourceHost, tunnelToHost;
  int? sourcePort, tunnelToPort;
  VoidCallback? connectHandler;
  StringCallback? connectError, onError, onDone;
  late Uint8ListCallback onMessage;

  SSHTunneledSocketImpl.fromClient(this.client) : clientOwner = false;

  SSHTunneledSocketImpl(
    Uri url,
    String login,
    String password, {
    String? key,
    StringCallback? print,
    StringCallback? debugPrint,
  }) : clientOwner = true {
    identity = key == null ? null : parsePem(key);
    client = SSHClient(
      socketInput: SocketImpl(),
      hostport: url,
      login: login,
      getPassword: () => utf8.encode(password) as Uint8List,
      // password == null ? null : () => utf8.encode(password) as Uint8List,
      loadIdentity: identity == null ? null : () => identity!,
      response: (m) {},
      disconnected: () {
        if (onDone != null) {
          onDone!('SSHTunnelledSocketImpl.client disconnected');
        }
      },
      startShell: false,
      success: openTunnel,
      print: print,
      debugPrint: debugPrint,
    );
  }

  @override
  bool get connected => channel != null;

  @override
  bool get connecting => connectHandler != null;

  @override
  void handleError(StringCallback errorHandler) => onError = errorHandler;

  @override
  void handleDone(StringCallback doneHandler) => onDone = doneHandler;

  @override
  void listen(Uint8ListCallback messageHandler) => onMessage = messageHandler;

  @override
  void send(String text) => sendRaw(utf8.encode(text) as Uint8List);

  @override
  void sendRaw(Uint8List raw) {
    if (shutdownSend) return;
    //client.debugPrint?.call('DEBUG SSHTunneledSocketImpl.send: ${String.fromCharCodes(raw)}');
    client.sendToChannel(channel!, raw);
  }

  @override
  void close() {
    if (clientOwner) {
      client.disconnect('close');
    } else if (channel != null) {
      client.closeChannel(channel!);
    }
  }

  /// Connects to [address] over SSH tunnel provided by [client].
  @override
  void connect(
    Uri address,
    VoidCallback connectCallback,
    StringCallback errorHandler, {
    int timeoutSeconds = 15,
    bool ignoreBadCert = false,
  }) {
    tunnelToHost = address.host;
    tunnelToPort = address.port;
    connectHandler = connectCallback;
    connectError = errorHandler;
    if (clientOwner) {
      client.socket!.connect(client.hostport!, client.onConnected, (error) {
        client.disconnect('connect error');
        if (connectError != null) connectError!(error);
      });
    } else {
      if (client.sessionChannel == null) {
        client.success.add(openTunnel);
      } else {
        openTunnel();
      }
    }
  }

  /// Sends [MSG_CHANNEL_OPEN_TCPIP] for [tunnelToHost]:[tunnelToPort].
  void openTunnel([String sourceHost = '127.0.0.1', int sourcePort = 1234]) {
    this.sourceHost = sourceHost;
    this.sourcePort = sourcePort;
    channel = client.openTcpChannel(
        sourceHost, sourcePort, tunnelToHost, tunnelToPort, (Uint8List? m) {
      //client.debugPrint?.call('DEBUG SSHTunneledSocketImpl.recv: ${String.fromCharCodes(m)}');
      //client.debugPrint?.call('DEBUG SSHTunneledSocketImpl.recvRaw(${m.length}) = $m');
      onMessage(m!);
    }, connected: () {
      if (connectHandler != null) connectHandler!();
      connectHandler = null;
      connectError = null;
    }, error: (String? description) {
      if (connectError != null) {
        connectError!(description);
      } else {
        onError!(description);
      }
      connectHandler = null;
      connectError = null;
    });
  }
}
