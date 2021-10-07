// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

// ignore_for_file: non_constant_identifier_names

import 'dart:async';
import 'dart:math';
import 'dart:convert';
import 'dart:typed_data';

import 'package:meta/meta.dart';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/agent.dart';
import 'package:dartssh2/src/identity.dart';
import 'package:dartssh2/src/protocol.dart';
import 'package:dartssh2/src/serializable.dart';
import 'package:dartssh2/src/socket.dart';
import 'package:dartssh2/src/ssh.dart';
import 'package:dartssh2/src/transport.dart';

typedef SSHPasswordRequestHandler = FutureOr<String> Function();

/// https://datatracker.ietf.org/doc/html/rfc4256#section-3.3
typedef SSHUserauthRequestHandler = FutureOr<List<String>> Function(
  SSHUserauthRequest request,
);

typedef SSHIdentityRequestHandler = SSHIdentity? Function();

typedef HostFingerprintHandler = FutureOr<bool> Function(int, Uint8List?);

class SSHUserauthRequest {
  SSHUserauthRequest({this.name, this.instruction, required this.prompts});

  final String? name;
  final String? instruction;
  final List<SSHAuthPrompt> prompts;
}

const kAuthMethodPassword = 'password';
const kAuthMethodPublicKey = 'publickey';
const kAuthMethodKeyboardInteractive = 'keyboard-interactive';
const kAuthMethodHostbased = 'hostbased';
const kAuthMethodNone = 'none';

/// The Secure Shell (SSH) is a protocol for secure remote login and
/// other secure network services over an insecure network.
class SSHClient extends SSHTransport with SSHAgentForwarding {
  /// width of the terminal window in characters
  int termWidth;

  /// height of the terminal window in characters
  int termHeight;

  /// The username to authenticate as.
  final String username;

  /// Set this field to enable the 'password' authentication method.
  final SSHPasswordRequestHandler? onPasswordRequest;

  /// Set this field to enable the 'keyboard-interactive' authentication method.
  final SSHUserauthRequestHandler? onUserauthRequest;

  /// Set this field to enable the 'publickey' authentication method.
  final SSHIdentityRequestHandler? loadIdentity;

  /// onHostFingerprint is called when the server's host key is received. Return
  /// true to accept the key, false to reject it.
  final HostFingerprintHandler? onHostFingerprint;

  /// Whether to start an interactive shell session on the SSH server after the
  /// connection is established. Default is true.
  final bool startShell;

  /// TERM environment variable value (e.g., vt100, xterm). 'xterm' by default.
  /// Use `Platform.environment['TERM']` if you want to use the value of your
  /// terminal or `xterm-256color` for better color support.
  final String termvar;

  /// Whether to enable agent forwarding.
  final bool agentForwarding;

  /// Whether to close the connection after the shell session is closed.
  /// Currently not supported.
  final bool closeOnDisconnect;

  SSHClient({
    Uri? hostname,
    int port = 22,
    required this.username,
    this.loadIdentity,
    this.onUserauthRequest,
    this.onPasswordRequest,
    this.onHostFingerprint,
    this.termvar = 'xterm',
    this.termWidth = 80,
    this.termHeight = 25,
    bool compress = false,
    this.agentForwarding = false,
    this.closeOnDisconnect = false,
    this.startShell = true,
    List<Forward>? forwardLocal,
    List<Forward>? forwardRemote,
    VoidCallback? success,
    VoidCallback? disconnected,
    ResponseCallback? response,
    StringCallback? print,
    StringCallback? debugPrint,
    StringCallback? tracePrint,
    SSHSocket? socketInput,
  }) : super(
          false,
          hostname: hostname,
          compress: compress,
          forwardLocal: forwardLocal,
          forwardRemote: forwardRemote,
          disconnected: disconnected,
          response: response,
          print: print,
          debugPrint: debugPrint,
          tracePrint: tracePrint,
          socket: socketInput,
        ) {
    if (success != null) {
      this.success.add(success);
    }

    // socket ??= (hostname!.hasScheme &&
    //         (hostname.scheme == 'ws' || hostname.scheme == 'wss'))
    //     ? SSHWebSocket()
    //     : SSHNativeSocket();

    // debugPrint?.call('Connecting to $hostname');

    // socket!.connect(
    //   hostname,
    //   onConnected,
    //   (error) => disconnect('connect error'),
    // );
  }

  // Parameters
  @internal
  List<VoidCallback> success = <VoidCallback>[];

  @internal
  bool acceptedHostkey = false;

  /// If we have tried to authenticate with "publickey" method.
  bool _triedAuthWithPublicKey = false;

  /// If we have tried to authenticate with "password" method.
  bool _triedAuthWithPassword = false;

  /// If we have tried to authenticate with "keyboard-interactive" method.
  bool _triedAuthWithKeyboardInteractive = false;

  /// If we have tried to authenticate with "none" method.
  bool _triedAuthWithNone = false;

  @internal
  void responseText(String text) {
    response?.call(Uint8List.fromList(text.codeUnits));
  }

  /// https://tools.ietf.org/html/rfc4253#section-6
  @override
  @internal
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
        tracePrint?.call('$hostname: MSG_CHANNEL_SUCCESS');
        break;

      case MSG_CHANNEL_FAILURE.ID:
        tracePrint?.call('$hostname: MSG_CHANNEL_FAILURE');
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
            '$hostname: unknown packet number: $packetId, len $packetLen');
        break;
    }
  }

  /// Initialize a shared-secret negotiation culminating with [MSG_NEWKEYS].
  @override
  @internal
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
      throw FormatException('$hostname: unknown kex method: $kexMethod');
    }
  }

  /// https://tools.ietf.org/html/rfc4253#section-8
  Future<void> handleMSG_KEXDH_REPLY(int packetId, Uint8List packet) async {
    if (state != SSHTransportState.FIRST_KEXREPLY &&
        state != SSHTransportState.KEXREPLY) {
      throw StateError('$hostname: unexpected state $state');
    }

    if (guessedS! && !guessedRightS!) {
      guessedS = false;
      this.print?.call('$hostname: server guessed wrong, ignoring packet');
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
      if (onHostFingerprint != null) {
        acceptedHostkey = await onHostFingerprint!(hostkeyType, fingerprint);
      } else {
        acceptedHostkey = true;
      }
    }

    sendNewKeys();
  }

  /// Completes X25519 key exchange.
  Uint8List? handleX25519MSG_KEX_ECDH_REPLY(MSG_KEX_ECDH_REPLY msg) {
    tracePrint?.call('<- $hostname: MSG_KEX_ECDH_REPLY for X25519DH');

    Uint8List? fingerprint;

    if (!acceptedHostkey) fingerprint = msg.kS;

    K = x25519dh.computeSecret(msg.qS!);
    if (!computeExchangeHashAndVerifyHostKey(msg.kS!, msg.hSig)) {
      throw FormatException('$hostname: verify hostkey failed');
    }

    return fingerprint;
  }

  /// Completes Elliptic-curve Diffie–Hellman key exchange.
  Uint8List? handleEcDhMSG_KEX_ECDH_REPLY(MSG_KEX_ECDH_REPLY msg) {
    tracePrint?.call('<- $hostname: MSG_KEX_ECDH_REPLY for ECDH');

    Uint8List? fingerprint;
    if (!acceptedHostkey) fingerprint = msg.kS;

    K = ecdh.computeSecret(msg.qS!);
    if (!computeExchangeHashAndVerifyHostKey(msg.kS!, msg.hSig)) {
      throw FormatException('$hostname: verify hostkey failed');
    }

    return fingerprint;
  }

  /// Completes Diffie-Hellman Group Exchange and begins key exchange.
  void handleDhGroupMSG_KEX_DH_GEX_GROUP(MSG_KEX_DH_GEX_GROUP msg) {
    tracePrint?.call('<- $hostname: MSG_KEX_DH_GEX_GROUP');

    initializeDiffieHellmanGroup(msg.p!, msg.g!, random);
    writeClearOrEncrypted(MSG_KEX_DH_GEX_INIT(dh.e));
  }

  /// Completes Diffie-Hellman key exchange.
  Uint8List? handleDhMSG_KEXDH_REPLY(MSG_KEXDH_REPLY msg) {
    tracePrint?.call('<- $hostname: MSG_KEXDH_REPLY');

    Uint8List? fingerprint;

    if (!acceptedHostkey) fingerprint = msg.kS;

    K = dh.computeSecret(msg.f);
    if (!computeExchangeHashAndVerifyHostKey(msg.kS!, msg.hSig)) {
      throw FormatException('$hostname: verify hostkey failed');
    }

    return fingerprint;
  }

  /// Handle accepted [MSG_SERVICE_REQUEST] sent in response to [MSG_NEWKEYS].
  void handleMSG_SERVICE_ACCEPT() {
    tracePrint?.call('<- $hostname: MSG_SERVICE_ACCEPT');

    if (identity == null && loadIdentity != null) {
      identity = loadIdentity!();
      debugPrint?.call('$hostname: loaded identity');
    }

    // Authentication method priority in first try:
    //   1. "publickey"
    //   3. "keyboard-interactive"
    //   2. "password"
    //   4. "none" if no other authentication method is provided.

    if (identity != null) {
      _triedAuthWithPublicKey = true;
      sendPublicKey();
      return;
    }

    if (onUserauthRequest != null) {
      _triedAuthWithKeyboardInteractive = true;
      sendKeyboardInteractive();
      return;
    }

    if (onPasswordRequest != null) {
      _triedAuthWithPassword = true;
      getThenSendPassword();
      return;
    }

    _triedAuthWithNone = true;
    sendNoneAuthenticationRequest();
  }

  /// If key authentication failed, then try password authentication.
  void handleMSG_USERAUTH_FAILURE(MSG_USERAUTH_FAILURE msg) {
    tracePrint?.call(
      '<- $hostname: MSG_USERAUTH_FAILURE: auth_left="${msg.authLeft}"',
    );

    // Authentication method priority on failure:
    //   1. "none"
    //   2. "publickey"
    //   3. "keyboard-interactive"
    //   4. "password"

    if (msg.authLeft.contains(kAuthMethodNone)) {
      if (!_triedAuthWithNone) {
        _triedAuthWithNone = true;
        sendNoneAuthenticationRequest();
        return;
      }
    }

    if (msg.authLeft.contains(kAuthMethodPublicKey)) {
      if (!_triedAuthWithPublicKey && identity != null) {
        _triedAuthWithPublicKey = true;
        sendPublicKey();
        return;
      }
    }

    if (msg.authLeft.contains(kAuthMethodKeyboardInteractive)) {
      if (!_triedAuthWithKeyboardInteractive && onUserauthRequest != null) {
        _triedAuthWithKeyboardInteractive = true;
        sendKeyboardInteractive();
        return;
      }
    }

    if (msg.authLeft.contains(kAuthMethodPassword)) {
      if (!_triedAuthWithPassword && onPasswordRequest != null) {
        _triedAuthWithPassword = true;
        getThenSendPassword();
        return;
      }
    }

    throw FormatException(
        '$hostname: authorization failed after trying all methods');
  }

  /// After successfull authentication, open the session channel and start compression.
  void handleMSG_USERAUTH_SUCCESS() {
    tracePrint?.call('<- $hostname: MSG_USERAUTH_SUCCESS');

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
  FutureOr<void> handleMSG_USERAUTH_INFO_REQUEST(
    MSG_USERAUTH_INFO_REQUEST request,
  ) async {
    tracePrint?.call('<- $hostname: $request');

    if (request.prompts.isEmpty || onUserauthRequest == null) {
      writeCipher(MSG_USERAUTH_INFO_RESPONSE(<Uint8List>[]));
    }

    final userAuthRequest = SSHUserauthRequest(
      name: request.name,
      instruction: request.instruction,
      prompts: request.prompts,
    );
    final responses = await onUserauthRequest!(userAuthRequest);
    sendUserauthInfoResponse(responses);
  }

  /// Logs any (unhandled) channel specific requests from server.
  void handleMSG_CHANNEL_REQUEST(MSG_CHANNEL_REQUEST msg) {
    tracePrint?.call(
        '<- $hostname: MSG_CHANNEL_REQUEST ${msg.requestType} wantReply=${msg.wantReply}');
  }

  /// Handles server-initiated [SSHChannel] to client.  e.g. for remote port forwarding,
  /// or SSH agent request.
  void handleMSG_CHANNEL_OPEN(
    MSG_CHANNEL_OPEN msg,
    SerializableInput? packetS,
  ) {
    tracePrint?.call('<- $hostname: MSG_CHANNEL_OPEN type=${msg.channelType}');
    if (msg.channelType == 'auth-agent@openssh.com' && agentForwarding) {
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
    if (agentForwarding) {
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

  /// Sends [MSG_USERAUTH_REQUEST] in "none" method.
  void sendNoneAuthenticationRequest() {
    writeCipher(
      MSG_USERAUTH_REQUEST(
        username,
        'ssh-connection',
        'none',
        '',
        Uint8List(0),
        Uint8List(0),
      ),
    );
  }

  Future<void> getThenSendPassword() async {
    if (onPasswordRequest == null) {
      debugPrint?.call('no password request handler');
      return;
    }

    final password = await onPasswordRequest!();
    sendPassword(password);
  }

  /// Sends [MSG_USERAUTH_REQUEST] with [password].
  void sendPassword(String pasword) {
    writeCipher(
      MSG_USERAUTH_REQUEST(
        username,
        'ssh-connection',
        'password',
        '',
        utf8.encode(pasword) as Uint8List,
        Uint8List(0),
      ),
    );
  }

  /// Request authentication in 'keyboard-interactive' method.
  void sendKeyboardInteractive() {
    debugPrint?.call('$hostname: Keyboard interactive');
    writeCipher(
      MSG_USERAUTH_REQUEST(
        username,
        'ssh-connection',
        'keyboard-interactive',
        '',
        Uint8List(0),
        Uint8List(0),
      ),
    );
  }

  /// Sends [MSG_USERAUTH_INFO_RESPONSE] with [responses] for [MSG_USERAUTH_INFO_REQUEST.prompts].
  void sendUserauthInfoResponse(List<String> responses) {
    writeCipher(
      MSG_USERAUTH_INFO_RESPONSE(
        responses.map(utf8.encode).cast<Uint8List>().toList(),
      ),
    );
  }

  /// Sends [MSG_USERAUTH_REQUEST] using [identity].
  void sendPublicKey() {
    final identity = this.identity;

    if (identity == null) {
      debugPrint?.call('$hostname: No identity');
      return;
    }

    _triedAuthWithPublicKey = true;

    if (identity.ed25519 != null) {
      debugPrint?.call('$hostname: Sending Ed25519 authorization request');
      final pubkey = identity.getEd25519PublicKey().toRaw();
      final challenge = deriveChallenge(
        sessionId!,
        username,
        'ssh-connection',
        'publickey',
        'ssh-ed25519',
        pubkey,
      );
      final sig = identity.signWithEd25519Key(challenge);
      writeCipher(
        MSG_USERAUTH_REQUEST(
          username,
          'ssh-connection',
          'publickey',
          'ssh-ed25519',
          pubkey,
          sig.toRaw(),
        ),
      );
    } else if (identity.ecdsaPrivate != null) {
      debugPrint?.call('$hostname: Sending ECDSA authorization request');
      final keyType = Key.name(identity.ecdsaKeyType);
      final pubkey = identity.getECDSAPublicKey().toRaw();
      final challenge = deriveChallenge(
        sessionId!,
        username,
        'ssh-connection',
        'publickey',
        keyType,
        pubkey,
      );
      final sig = identity.signWithECDSAKey(challenge, secureRandom);
      writeCipher(
        MSG_USERAUTH_REQUEST(
          username,
          'ssh-connection',
          'publickey',
          keyType,
          pubkey,
          sig.toRaw(),
        ),
      );
    } else if (identity.rsaPrivate != null) {
      debugPrint?.call('$hostname: Sending RSA authorization request');
      final pubkey = identity.getRSAPublicKey().toRaw();
      final challenge = deriveChallenge(
        sessionId!,
        username,
        'ssh-connection',
        'publickey',
        'ssh-rsa',
        pubkey,
      );
      final sig = identity.signWithRSAKey(challenge);
      writeCipher(
        MSG_USERAUTH_REQUEST(
          username,
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
    if (sessionChannel != null) {
      sendToChannel(sessionChannel!, b);
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

/// Implement same [SSHSocket] as actual [Socket] but over [SSHClient] tunnel.
class SSHTunneledSocket extends SSHSocket {
  bool shutdownSend = false, shutdownRecv = false;
  late SSHClient client;
  SSHIdentity? identity;
  SSHChannel? channel;
  String? sourceHost, tunnelToHost;
  int? sourcePort, tunnelToPort;
  VoidCallback? connectHandler;
  StringCallback? connectError, onError, onDone;
  late Uint8ListCallback onMessage;

  SSHTunneledSocket.fromClient(this.client);

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
  void send(String text) => sendBinary(utf8.encode(text) as Uint8List);

  @override
  void sendBinary(Uint8List data) {
    if (shutdownSend) return;
    //client.debugPrint?.call('DEBUG SSHTunneledSocketImpl.send: ${String.fromCharCodes(raw)}');
    client.sendToChannel(channel!, data);
  }

  @override
  void close() {
    client.closeChannel(channel!);
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
    if (client.sessionChannel == null) {
      client.success.add(_openTunnel);
    } else {
      _openTunnel();
    }
  }

  /// Sends [MSG_CHANNEL_OPEN_TCPIP] for [tunnelToHost]:[tunnelToPort].
  void _openTunnel([String sourceHost = '127.0.0.1', int sourcePort = 1234]) {
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
