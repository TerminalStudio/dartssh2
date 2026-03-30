import 'dart:async';
import 'dart:collection';
import 'dart:typed_data';

import 'package:dartssh2/src/http/http_client.dart';
import 'package:dartssh2/src/sftp/sftp_client.dart';
import 'package:dartssh2/src/dynamic_forward.dart';
import 'package:dartssh2/src/ssh_algorithm.dart';
import 'package:dartssh2/src/ssh_agent.dart';
import 'package:dartssh2/src/ssh_channel.dart';
import 'package:dartssh2/src/message/base.dart';
import 'package:dartssh2/src/ssh_channel_id.dart';
import 'package:dartssh2/src/ssh_errors.dart';
import 'package:dartssh2/src/ssh_forward.dart';
import 'package:dartssh2/src/ssh_hostkey.dart';
import 'package:dartssh2/src/ssh_keepalive.dart';
import 'package:dartssh2/src/ssh_key_pair.dart';
import 'package:dartssh2/src/ssh_session.dart';
import 'package:dartssh2/src/ssh_transport.dart';
import 'package:dartssh2/src/ssh_userauth.dart';
import 'package:dartssh2/src/socket/ssh_socket.dart';
import 'package:dartssh2/src/utils/async_queue.dart';
import 'package:meta/meta.dart';

/// Type definition for the host keys handler.
typedef SSHHostKeysHandler = void Function(List<SSHHostKey> hostKeys);

/// https://datatracker.ietf.org/doc/html/rfc4252#section-8
typedef SSHPasswordRequestHandler = FutureOr<String?> Function();

typedef SSHChangePasswordRequestHandler = FutureOr<SSHChangePasswordResponse?>
    Function(String prompt);

/// https://datatracker.ietf.org/doc/html/rfc4256#section-3.3
typedef SSHUserInfoRequestHandler = FutureOr<List<String>?> Function(
  SSHUserInfoRequest request,
);

/// https://datatracker.ietf.org/doc/html/rfc4252#section-5.4
typedef SSHUserauthBannerHandler = void Function(String banner);

typedef SSHAuthenticatedHandler = void Function();

typedef SSHRemoteConnectionFilter = bool Function(String host, int port);

typedef SSHX11ForwardHandler = void Function(SSHX11Channel channel);

// /// Function called when the host has sent additional host keys after the initial
// /// key exchange.
// typedef SSHHostKeysHandler = void Function(List<Uint8List>);

const _initialWindowSize = 1024 * 1024 * 2;

const _maximumPacketSize = 32768;

class SSHPtyConfig {
  /// Type of terminal, for example 'xterm', 'xterm-256color'.
  final String type;

  /// Width of the terminal in number of columns.
  final int width;

  /// Height of the terminal in number of rows.
  final int height;

  /// Width of the terminal in pixels. 0 if unknown.
  final int pixelWidth;

  /// Height of the terminal in pixels. 0 if unknown.
  final int pixelHeight;

  const SSHPtyConfig({
    this.type = 'xterm-256color',
    this.width = 80,
    this.height = 24,
    this.pixelWidth = 0,
    this.pixelHeight = 0,
  });
}

class SSHX11Config {
  /// Whether only a single forwarded X11 connection should be accepted.
  final bool singleConnection;

  /// X11 authentication protocol name.
  final String authenticationProtocol;

  /// X11 authentication cookie value.
  final String authenticationCookie;

  /// X11 screen number.
  final int screenNumber;

  const SSHX11Config({
    required this.authenticationCookie,
    this.singleConnection = false,
    this.authenticationProtocol = 'MIT-MAGIC-COOKIE-1',
    this.screenNumber = 0,
  });
}

class SSHRunResult {
  /// Combined output stream based on [SSHClient.runWithResult] capture flags.
  final Uint8List output;

  /// Captured stdout bytes. Empty when stdout capture is disabled.
  final Uint8List stdout;

  /// Captured stderr bytes. Empty when stderr capture is disabled.
  final Uint8List stderr;

  /// Exit code reported by the remote process if available.
  final int? exitCode;

  /// Exit signal reported by the remote process if available.
  final SSHSessionExitSignal? exitSignal;

  const SSHRunResult({
    required this.output,
    required this.stdout,
    required this.stderr,
    required this.exitCode,
    required this.exitSignal,
  });
}

class SSHClient {
  /// RFC 4252 recommended authentication timeout period
  static const Duration defaultAuthTimeout = Duration(minutes: 10);

  /// Default handshake timeout. Separates transport handshake timeout from
  /// authentication timeout for better robustness.
  static const Duration defaultHandshakeTimeout = Duration(seconds: 30);

  /// RFC 4252 recommended maximum authentication attempts per session
  static const int defaultMaxAuthAttempts = 20;

  final SSHSocket socket;

  /// The username to authenticate as.
  final String username;

  /// Function invoked with debug messages.
  final SSHPrintHandler? printDebug;

  /// Function invoked with network traffic messages.
  final SSHPrintHandler? printTrace;

  /// Crypto algorithms available for the client.
  final SSHAlgorithms algorithms;

  /// Function called when the first host key is received. Return true to accept
  /// the host key, false to reject it and close the connection.
  ///
  /// Security note: This is required for safety. If not provided, the
  /// connection will be rejected by default at host key verification time.
  final SSHHostkeyVerifyHandler? onVerifyHostKey;

  /// List of key pairs to use for authentication. Set this field to enable
  /// authentication with public key.
  final List<SSHKeyPair>? identities;

  /// Set this field to enable the 'password' authentication method. Return null
  /// to skip to the next available authentication method.
  final SSHPasswordRequestHandler? onPasswordRequest;

  /// Set this field to enable setting new passwords when the server requests
  /// changing password when using the 'password' authentication method. Return
  /// null to skip to the next available authentication method.
  final SSHChangePasswordRequestHandler? onChangePasswordRequest;

  /// Set this field to enable the 'keyboard-interactive' authentication method.
  /// This may be called multiple times to request additional prompts. Return
  /// null to skip to the next available authentication method.
  final SSHUserInfoRequestHandler? onUserInfoRequest;

  /// The SSH server may send banner message at any time before authentication
  /// is successful. Set this field to receive the banner message.
  final SSHUserauthBannerHandler? onUserauthBanner;

  /// A [Future] that completes normally when the client is connected to the
  // Future<void> get handshake => _handshakeCompleter.future;

  /// Function called when authentication is complete.
  final SSHAuthenticatedHandler? onAuthenticated;

  /// Function called when the server opens an incoming forwarded X11 channel.
  final SSHX11ForwardHandler? onX11Forward;

  /// Optional handler for SSH agent forwarding requests.
  final SSHAgentHandler? agentHandler;

  /// The interval at which to send a keep-alive message through the [ping]
  /// method. Set this to null to disable automatic keep-alive messages.
  final Duration? keepAliveInterval;

  /// Key pairs to use for hostbased authentication.
  final List<SSHKeyPair>? hostbasedIdentities;

  /// Hostname used for hostbased authentication.
  final String? hostName;

  /// Username of clinet host used for hostbased authentication.
  final String? userNameOnClientHost;

  /// Auth timeout, 10m by default.
  final Duration authTimeout;

  /// Handshake timeout, 30s by default. This only covers the SSH transport
  /// handshake (version exchange, KEX, host key verification, NEWKEYS), and is
  /// independent from [authTimeout].
  final Duration handshakeTimeout;

  /// Max auth attempts, 20 by default.
  final int maxAuthAttempts;

  /// Function called when additional host keys are received. This is an OpenSSH
  /// extension. May not be called if the server does not support the extension.
  final SSHHostKeysHandler? onHostKeys;

  /// Allow to disable hostkey verification, which can be slow in debug mode.
  final bool disableHostkeyVerification;

  /// Identification string advertised during the SSH version exchange (the part
  /// after `SSH-2.0-`). Defaults to `'DartSSH_2.0'`
  String get ident => _ident;

  /// A [Future] that completes when the transport is closed, or when an error
  /// occurs. After this [Future] completes, [isClosed] will be true and no more
  /// data can be sent or received.
  Future<void> get done => _transport.done;

  /// true if the connection is closed normally or due to an error.
  bool get isClosed => _transport.isClosed;

  SSHClient(
    this.socket, {
    required this.username,
    this.printDebug,
    this.printTrace,
    this.algorithms = const SSHAlgorithms(),
    this.onVerifyHostKey,
    this.identities,
    this.hostbasedIdentities,
    this.hostName,
    this.userNameOnClientHost,
    this.onPasswordRequest,
    this.onChangePasswordRequest,
    this.onUserInfoRequest,
    this.onUserauthBanner,
    this.onAuthenticated,
    this.keepAliveInterval = const Duration(seconds: 10),

    /// Authentication timeout period. RFC 4252 recommends 10 minutes.
    this.authTimeout = defaultAuthTimeout,

    /// Handshake timeout period. Defaults to 30s.
    this.handshakeTimeout = defaultHandshakeTimeout,

    /// Maximum authentication attempts. RFC 4252 recommends 20 attempts.
    this.maxAuthAttempts = defaultMaxAuthAttempts,
    this.onHostKeys,
    this.disableHostkeyVerification = false,
    this.onX11Forward,
    this.agentHandler,
    String ident = 'DartSSH_2.0',
  }) : _ident = _validateIdent(ident) {
    _transport = SSHTransport(
      socket,
      isServer: false,
      printDebug: printDebug,
      printTrace: printTrace,
      algorithms: algorithms,
      onVerifyHostKey: onVerifyHostKey,
      onReady: _handleTransportReady,
      onPacket: _handlePacket,
      disableHostkeyVerification: disableHostkeyVerification,
      version: _ident,
    );

    _transport.done.then(
      (_) => _handleTransportClosed(null),
      onError: (e) => _handleTransportClosed(
        e is SSHError ? e : SSHSocketError(e),
      ),
    );

    _authenticated.future.catchError(
      (error, stackTrace) => _transport.closeWithError(error, stackTrace),
    );

    if (identities != null) {
      _keyPairsLeft.addAll(identities!);
    }

    // 初始化 hostbased 密钥队列
    if (hostbasedIdentities != null) {
      _hostbasedKeyPairsLeft.addAll(hostbasedIdentities!);
    }

    // 添加认证超时定时器
    _authTimeoutTimer = Timer(authTimeout, _onAuthTimeout);

    // 添加握手超时定时器（与认证超时分离）
    _handshakeTimeoutTimer = Timer(handshakeTimeout, _onHandshakeTimeout);
  }

  static String _validateIdent(String ident) {
    if (ident.isEmpty) {
      throw ArgumentError.value(
        ident,
        'ident',
        'must not be empty',
      );
    }

    if (ident.startsWith('SSH-')) {
      throw ArgumentError.value(
        ident,
        'ident',
        'must not include SSH- prefix',
      );
    }

    if (ident.contains('\r') || ident.contains('\n')) {
      throw ArgumentError.value(
        ident,
        'ident',
        'must not contain carriage return or newline characters',
      );
    }

    return ident;
  }

  final String _ident;

  final _hostbasedKeyPairsLeft = Queue<SSHKeyPair>();
  Timer? _authTimeoutTimer;
  Timer? _handshakeTimeoutTimer;
  int _authAttempts = 0;

  late final SSHTransport _transport;

  /// A [Completer] that completes when the client has authenticated, or
  /// completes with an error if the client could not authenticate.
  final _authenticated = Completer<void>();

  final _globalRequestReplyQueue = AsyncQueue<SSHMessage>();

  final _channelIdAllocator = SSHChannelIdAllocator();

  final _channelOpenReplyWaiters = <int, Completer<SSHMessage>>{};

  final _channels = <int, SSHChannelController>{};

  final _authMethodsLeft = Queue<SSHAuthMethod>();

  final _keyPairsLeft = Queue<SSHKeyPair>();

  final _remoteForwards = <SSHRemoteForward>{};

  late final _keepAlive = keepAliveInterval != null
      ? SSHKeepAlive(ping: ping, interval: keepAliveInterval!)
      : null;

  SSHAuthMethod? _currentAuthMethod;

  /// A [Future] that completes when the client has authenticated, or
  /// completes with an error if the client could not authenticate.
  Future<void> get authenticated => _authenticated.future;

  /// Identification string sent by the other side. For example,
  /// "SSH-2.0-OpenSSH_7.4p1". May be null if the handshake has not yet
  /// completed.
  String? get remoteVersion => _transport.remoteVersion;

  /// Request connections to a port on the other side be forwarded to the local
  /// side.
  /// Set [host] to null to listen on all interfaces, `"0.0.0.0"` to
  /// listen on all IPv4 interfaces, `"::"` to listen on all IPv6 interfaces,
  /// and `"localhost"` to listen on the loopback interface on all protocols.
  /// Set [port] to null to listen on a random port.
  Future<SSHRemoteForward?> forwardRemote({
    String? host,
    int? port,
    SSHRemoteConnectionFilter? filter,
  }) async {
    await _authenticated.future;

    // Lisning on all interfaces if not specified.
    host ??= '';

    // Lisning on a random port if not specified.
    port ??= 0;

    _sendMessage(SSH_Message_Global_Request.tcpipForward(host, port));
    final reply = await _globalRequestReplyQueue.next;

    if (reply is SSH_Message_Request_Failure) return null;

    if (reply is! SSH_Message_Request_Success) {
      throw SSHStateError('Unexpected reply to tcpip-forward request: $reply');
    }

    final reader = SSHMessageReader(reply.requestData);
    final assignedPort = port != 0 ? port : reader.readUint32();

    final remoteForward = SSHRemoteForward(this, host, assignedPort, filter);
    _remoteForwards.add(remoteForward);

    return remoteForward;
  }

  /// Cancel a previous request to forward connections to a port on the other
  /// side. Returns [true] if successful, [false] otherwise.
  /// See also: [forwardRemote].
  Future<bool> cancelForwardRemote(SSHRemoteForward forward) async {
    await _authenticated.future;

    if (!_remoteForwards.remove(forward)) return false;

    _sendMessage(
      SSH_Message_Global_Request.cancelTcpipForward(
        bindAddress: forward.host,
        bindPort: forward.port,
      ),
    );

    final reply = await _globalRequestReplyQueue.next;
    if (reply is SSH_Message_Request_Failure) {
      return false;
    }

    return true;
  }

  /// Forward connections to a [localHost]:[localPort] to [remoteHost]:[remotePort]
  /// [localHost] and [localPort] are only required by the protocol and do not
  /// need to be specified in most cases.
  Future<SSHForwardChannel> forwardLocal(
    String remoteHost,
    int remotePort, {
    String localHost = 'localhost',
    int localPort = 0,
  }) async {
    await _authenticated.future;
    final channelController = await _openForwardLocalChannel(
      localHost,
      localPort,
      remoteHost,
      remotePort,
    );
    return SSHForwardChannel(channelController.channel);
  }

  /// Start a local SOCKS5 server that forwards outbound `CONNECT` requests
  /// through this SSH connection.
  ///
  /// This is similar to `ssh -D`. Only SOCKS5 with `NO AUTH` and `CONNECT`
  /// is supported. Use [filter] to optionally deny specific target
  /// destinations. Use [options] to tune timeouts and connection limits.
  ///
  /// Not supported on platforms without `dart:io`.
  Future<SSHDynamicForward> forwardDynamic({
    String bindHost = '127.0.0.1',
    int? bindPort,
    SSHDynamicForwardOptions options = const SSHDynamicForwardOptions(),
    SSHDynamicConnectionFilter? filter,
  }) async {
    await _authenticated.future;
    return startDynamicForward(
      bindHost: bindHost,
      bindPort: bindPort,
      options: options,
      filter: filter,
      dial: forwardLocal,
    );
  }

  /// Forward local connections to a remote Unix domain socket at
  /// [remoteSocketPath] on the remote side via a
  /// `direct-streamlocal@openssh.com` channel.
  ///
  /// This is the equivalent of `ssh -L localPort:remoteSocketPath`.
  Future<SSHForwardChannel> forwardLocalUnix(
    String remoteSocketPath,
  ) async {
    await _authenticated.future;
    final channelController = await _openForwardLocalUnixChannel(
      remoteSocketPath,
    );
    return SSHForwardChannel(channelController.channel);
  }

  /// Execute [command] on the remote side. Returns a [SSHChannel] that can be
  /// used to read and write to the remote side.
  Future<SSHSession> execute(
    String command, {
    SSHPtyConfig? pty,
    SSHX11Config? x11,
    Map<String, String>? environment,
  }) async {
    await _authenticated.future;

    final channelController = await _openSessionChannel();

    if (environment != null) {
      for (var pair in environment.entries) {
        final envOk = await channelController.sendEnv(pair.key, pair.value);
        if (!envOk) {
          channelController.close();
          throw SSHChannelRequestError(
            'Failed to set environment variable: ${pair.key}',
          );
        }
      }
    }

    if (agentHandler != null) {
      final agentOk = await channelController.sendAgentForwardingRequest();
      if (!agentOk) {
        channelController.close();
        throw SSHChannelRequestError('Failed to request agent forwarding');
      }
    }

    if (pty != null) {
      final ptyOk = await channelController.sendPtyReq(
        terminalType: pty.type,
        terminalWidth: pty.width,
        terminalHeight: pty.height,
        terminalPixelWidth: pty.pixelWidth,
        terminalPixelHeight: pty.pixelHeight,
      );
      if (!ptyOk) {
        channelController.close();
        throw SSHChannelRequestError('Failed to start pty');
      }
    }

    if (x11 != null) {
      final x11Ok = await channelController.sendX11Req(
        singleConnection: x11.singleConnection,
        authenticationProtocol: x11.authenticationProtocol,
        authenticationCookie: x11.authenticationCookie,
        screenNumber: x11.screenNumber,
      );
      if (!x11Ok) {
        channelController.close();
        throw SSHChannelRequestError('Failed to request x11 forwarding');
      }
    }

    final success = await channelController.sendExec(command);
    if (!success) {
      channelController.close();
      throw SSHChannelRequestError('Failed to execute');
    }

    return SSHSession(channelController.channel);
  }

  /// Start a shell on the remote side. Returns a [SSHSession] that can be
  /// used to read, write and control the pty on the remote side.
  Future<SSHSession> shell({
    SSHPtyConfig? pty = const SSHPtyConfig(),
    SSHX11Config? x11,
    Map<String, String>? environment,
  }) async {
    await _authenticated.future;

    final channelController = await _openSessionChannel();

    if (environment != null) {
      for (var pair in environment.entries) {
        final envOk = await channelController.sendEnv(pair.key, pair.value);
        if (!envOk) {
          channelController.close();
          throw SSHChannelRequestError(
            'Failed to set environment variable: ${pair.key}',
          );
        }
      }
    }

    if (agentHandler != null) {
      final agentOk = await channelController.sendAgentForwardingRequest();
      if (!agentOk) {
        channelController.close();
        throw SSHChannelRequestError('Failed to request agent forwarding');
      }
    }

    if (pty != null) {
      final ok = await channelController.sendPtyReq(
        terminalType: pty.type,
        terminalWidth: pty.width,
        terminalHeight: pty.height,
        terminalPixelWidth: pty.pixelWidth,
        terminalPixelHeight: pty.pixelHeight,
      );
      if (!ok) {
        channelController.close();
        throw SSHChannelRequestError('Failed to start pty');
      }
    }

    if (x11 != null) {
      final x11Ok = await channelController.sendX11Req(
        singleConnection: x11.singleConnection,
        authenticationProtocol: x11.authenticationProtocol,
        authenticationCookie: x11.authenticationCookie,
        screenNumber: x11.screenNumber,
      );
      if (!x11Ok) {
        channelController.close();
        throw SSHChannelRequestError('Failed to request x11 forwarding');
      }
    }

    if (!await channelController.sendShell()) {
      channelController.close();
      throw SSHChannelRequestError('Failed to start shell');
    }

    return SSHSession(channelController.channel);
  }

  Future<void> subsystem(String subsystem) async {
    await _authenticated.future;

    final channelController = await _openSessionChannel();
    channelController.sendSubsystem(subsystem);
  }

  /// Open a new SFTP session. Returns a [SftpClient] that can be used to
  /// interact with the remote side.
  Future<SftpClient> sftp() async {
    await _authenticated.future;

    final channelController = await _openSessionChannel();
    channelController.sendSubsystem('sftp');

    return SftpClient(
      channelController.channel,
      printDebug: printDebug,
      printTrace: printTrace,
    );
  }

  /// Create a new [SSHHttpClient] that can be used to make HTTP requests
  /// that are tunneled over the SSH connection. The returned [SSHHttpClient]
  /// is a very basic implementation, only intended for making simple requests.
  SSHHttpClient httpClient() {
    return SSHHttpClient(this);
  }

  /// Execute [command] on the remote side non-interactively. Returns a
  /// [Future<Uint8List>] that completes with the combined command output.
  /// This is a convenience method over [execute]. If [stdout] is false,
  /// the standard output of the command will be ignored. If [stderr] is
  /// false, the standard error of the command will be ignored.
  ///
  /// Use [runWithResult] when you need separate stdout/stderr bytes or exit
  /// metadata (`exitCode`/`exitSignal`).
  Future<Uint8List> run(
    String command, {
    bool runInPty = false,
    bool stdout = true,
    bool stderr = true,
    Map<String, String>? environment,
  }) async {
    final result = await runWithResult(
      command,
      runInPty: runInPty,
      stdout: stdout,
      stderr: stderr,
      environment: environment,
    );

    return result.output;
  }

  /// Execute [command] on the remote side non-interactively and return
  /// output together with exit metadata.
  Future<SSHRunResult> runWithResult(
    String command, {
    bool runInPty = false,
    bool stdout = true,
    bool stderr = true,
    Map<String, String>? environment,
  }) async {
    final session = await execute(
      command,
      pty: runInPty ? const SSHPtyConfig() : null,
      environment: environment,
    );

    final outputBuilder = BytesBuilder(copy: false);
    final stdoutBuilder = BytesBuilder(copy: false);
    final stderrBuilder = BytesBuilder(copy: false);
    final stdoutDone = Completer<void>();
    final stderrDone = Completer<void>();

    session.stdout.listen(
      stdout
          ? (data) {
              outputBuilder.add(data);
              stdoutBuilder.add(data);
            }
          : (_) {},
      onDone: stdoutDone.complete,
      onError: stdoutDone.completeError,
    );

    session.stderr.listen(
      stderr
          ? (data) {
              outputBuilder.add(data);
              stderrBuilder.add(data);
            }
          : (_) {},
      onDone: stderrDone.complete,
      onError: stderrDone.completeError,
    );

    await stdoutDone.future;
    await stderrDone.future;
    await session.done;

    return SSHRunResult(
      output: outputBuilder.takeBytes(),
      stdout: stdoutBuilder.takeBytes(),
      stderr: stderrBuilder.takeBytes(),
      exitCode: session.exitCode,
      exitSignal: session.exitSignal,
    );
  }

  /// Send a empty message to the server to keep the connection alive.
  Future<void> ping() async {
    await _authenticated.future;
    _sendMessage(SSH_Message_Global_Request.keepAlive());
    await _globalRequestReplyQueue.next;
  }

  /// Shutdown the entire SSH connection. Sessions and channels will also be
  /// closed immediately.
  void close() {
    _authTimeoutTimer?.cancel();
    _handshakeTimeoutTimer?.cancel();
    _closeChannels();
    _transport.close();
  }

  /// Close all channels that are currently open.
  void _closeChannels() {
    for (final channel in _channels.values) {
      channel.destroy();
      _channelIdAllocator.release(channel.localId);
    }

    _channels.clear();
  }

  void _handleTransportReady() {
    printDebug?.call('SSHClient._onTransportReady');
    // 握手完成，取消握手超时定时器
    _handshakeTimeoutTimer?.cancel();
    _handshakeTimeoutTimer = null;
    _requestAuthentication();
  }

  void _handleTransportClosed(SSHError? error) {
    printDebug?.call('SSHClient._onTransportClosed');
    _handshakeTimeoutTimer?.cancel();
    _handshakeTimeoutTimer = null;
    _authTimeoutTimer?.cancel();
    _authTimeoutTimer = null;
    if (!_authenticated.isCompleted) {
      final currentMethod = _currentAuthMethod != null
          ? "Current method: ${_currentAuthMethod!.name}"
          : "No auth method tried";
      final attempts = _authAttempts > 0
          ? "After $_authAttempts attempts"
          : "No attempts made";

      _authenticated.completeError(
        SSHAuthAbortError(
            'Connection closed before authentication. $currentMethod. $attempts',
            error),
      );
    }
    _keepAlive?.stop();

    // Complete any pending channel-open waiters so callers (e.g.
    // forwardLocalUnix) don't hang forever when the connection drops.
    for (final entry in _channelOpenReplyWaiters.entries) {
      if (!entry.value.isCompleted) {
        entry.value.completeError(error ??
            SSHStateError('Connection closed while waiting for channel open'));
      }
    }
    _channelOpenReplyWaiters.clear();

    // Fail any pending global request replies (e.g. ping, forwardRemote).
    _globalRequestReplyQueue.failAll(error ??
        SSHStateError(
            'Connection closed while waiting for global request reply'));

    // Fail pending request replies for each channel.
    for (final controller in _channels.values) {
      controller.failPendingRequestReplies(error ??
          SSHStateError(
              'Connection closed while waiting for channel request reply'));
    }

    try {
      _closeChannels();
    } catch (e) {
      printDebug?.call("SSHClient::_handleTransportClosed - error: $e");
    }
  }

  void _onHandshakeTimeout() {
    // 若在握手阶段一直未就绪，则返回握手超时错误并关闭连接
    if (_authenticated.isCompleted) return;
    final msg =
        'Handshake timed out after ${handshakeTimeout.inSeconds} seconds.';
    _authenticated.completeError(SSHHandshakeError(msg));
    // 认证阶段不会开始，取消其定时器以避免误触发
    _authTimeoutTimer?.cancel();
    _transport.closeWithError(SSHHandshakeError(msg));
  }

  void _handlePacket(Uint8List payload) {
    try {
      _dispatchMessage(payload);
    } catch (e) {
      rethrow;
    }
  }

  /// Handles a raw SSH packet. This method is only exposed for testing purposes.
  @visibleForTesting
  void handlePacket(Uint8List packet) => _handlePacket(packet);

  void _sendMessage(SSHMessage message) {
    printTrace?.call('-> $socket: $message');
    _transport.sendPacket(message.encode());
  }

  void _catch(FutureOr<dynamic> Function() fn) {
    Future.sync(fn).catchError((e, st) {
      _transport.closeWithError(SSHInternalError(e), st);
    });
  }

  void _dispatchMessage(Uint8List message) {
    final messageId = SSHMessage.readMessageId(message);
    switch (messageId) {
      case SSH_Message_Service_Accept.messageId:
        return _handleServiceAccept(message);
      case SSH_Message_Userauth_Success.messageId:
        return _handleUserauthSuccess();
      case SSH_Message_Userauth_Failure.messageId:
        return _handleUserauthFailure(message);
      case SSH_Message_Userauth_Passwd_ChangeReq.messageId:
        return _handleUserauthIntermidiate(message);
      case SSH_Message_Userauth_Banner.messageId:
        return _handleUserauthBanner(message);
      case SSH_Message_Global_Request.messageId:
        return _handleGlobalRequest(message);
      case SSH_Message_Request_Success.messageId:
        return _handleGlobalRequestSuccess(message);
      case SSH_Message_Request_Failure.messageId:
        return _handleGlobalRequestFailure(message);
      case SSH_Message_Channel_Open.messageId:
        return _handleChannelOpen(message);
      case SSH_Message_Channel_Confirmation.messageId:
        return _handleChannelConfirmation(message);
      case SSH_Message_Channel_Open_Failure.messageId:
        return _handleChannelOpenFailure(message);
      case SSH_Message_Channel_Window_Adjust.messageId:
        return _handleChannelWindowAdjust(message);
      case SSH_Message_Channel_Success.messageId:
        return _handleChannelSuccess(message);
      case SSH_Message_Channel_Failure.messageId:
        return _handleChannelFailure(message);
      case SSH_Message_Channel_Data.messageId:
        return _handleChannelData(message);
      case SSH_Message_Channel_Extended_Data.messageId:
        return _handleChannelExtendedData(message);
      case SSH_Message_Channel_EOF.messageId:
        return _handleChannelEOF(message);
      case SSH_Message_Channel_Close.messageId:
        return _handleChannelClose(message);
      case SSH_Message_Channel_Request.messageId:
        return _handleChannelRequest(message);
      default:
        printDebug?.call('unknown messageId: $messageId');
    }
  }

  void _handleServiceAccept(Uint8List payload) {
    final message = SSH_Message_Service_Accept.decode(payload);
    printTrace?.call('<- $socket: $message');

    switch (message.serviceName) {
      case 'ssh-userauth':
        // Service has been accepted, start authentication.
        return _startAuthentication();
      default:
        printDebug?.call('Unknown serviceName: ${message.serviceName}');
        _transport.closeWithError(SSHStateError(
            'Server accepted unknown service: ${message.serviceName}'));
    }
  }

  void _handleUserauthSuccess() {
    printTrace?.call('<- $socket: SSH_Message_Userauth_Success');
    printDebug?.call('SSHClient._handleUserauthSuccess');
    _authTimeoutTimer?.cancel();
    _authenticated.complete();
    onAuthenticated?.call();
    _keepAlive?.start();
  }

  void _handleUserauthFailure(Uint8List payload) {
    final message = SSH_Message_Userauth_Failure.decode(payload);
    printTrace?.call('<- $socket: $message');
    printDebug?.call('SSHClient._handleUserauthFailure');

    // RFC 4252: Process the list of methods that can continue
    final availableMethods = message.methodsLeft;
    printDebug?.call('Server supports methods: ${availableMethods.join(', ')}');

    // Update our authentication strategy based on server's response
    _updateAuthMethodsBasedOnServerResponse(
        availableMethods, message.partialSuccess);

    _tryNextAuthMethod();
  }

  void _handleUserauthIntermidiate(Uint8List payload) {
    printDebug?.call('SSHClient._handleUserauthIntermidiate');

    switch (_currentAuthMethod) {
      case SSHAuthMethod.password:
        return _catch(() => _handleUserauthPasswordChangeRequest(payload));
      case SSHAuthMethod.keyboardInteractive:
        return _catch(() => _handleUserauthInfoRequest(payload));
      default:
        printDebug?.call('unknown auth method: $_currentAuthMethod');
    }
  }

  Future<void> _handleUserauthPasswordChangeRequest(Uint8List payload) async {
    printDebug?.call('SSHClient._handleUserauthPasswordChangeRequest');

    // RFC 4252: Password change should be disabled if no confidentiality or MAC
    if (!_hasConfidentiality || !_hasMacProtection) {
      printDebug
          ?.call('Refusing password change - insufficient transport security');
      _tryNextAuthMethod();
      return;
    }

    final message = SSH_Message_Userauth_Passwd_ChangeReq.decode(payload);
    printTrace?.call('<- $socket: $message');

    if (onChangePasswordRequest == null) {
      printDebug?.call('No password change handler, trying next method');
      return _tryNextAuthMethod();
    }

    final response = await onChangePasswordRequest!(message.prompt);
    if (response == null) {
      printDebug?.call('Password change canceled, trying next method');
      return _tryNextAuthMethod();
    }

    _sendMessage(SSH_Message_Userauth_Request.newPassword(
      user: username,
      oldPassword: response.oldPassword,
      newPassword: response.newPassword,
    ));
  }

  Future<void> _handleUserauthInfoRequest(Uint8List payload) async {
    printDebug?.call('SSHClient._handleUserauthInfoRequest');
    final message = SSH_Message_Userauth_InfoRequest.decode(payload);
    printTrace?.call('<- $socket: $message');

    final responses = await onUserInfoRequest!(
      SSHUserInfoRequest(message.name, message.instruction, message.prompts),
    );

    if (responses == null) return _tryNextAuthMethod();

    if (responses.length != message.prompts.length) {
      throw ArgumentError(
        'responses.length (${responses.length}) != message.prompts.length (${message.prompts.length})',
      );
    }

    _sendMessage(SSH_Message_Userauth_InfoResponse(responses: responses));
  }

  void _handleUserauthBanner(Uint8List payload) {
    final message = SSH_Message_Userauth_Banner.decode(payload);
    printTrace?.call('<- $socket: $message');

    // RFC 4252: Apply control character filtering to prevent terminal attacks
    final sanitizedMessage = _sanitizeBannerMessage(message.message);
    printDebug?.call(
        'Received authentication banner (${message.message.length} chars, ${sanitizedMessage.length} after sanitization)');

    onUserauthBanner?.call(sanitizedMessage);
  }

  void _handleGlobalRequest(Uint8List payload) {
    final message = SSH_Message_Global_Request.decode(payload);
    printTrace?.call('<- $socket: $message');

    bool handled = false;
    switch (message.requestName) {
      case 'hostkeys-00@openssh.com':
        // This request type typically has wantReply = false.
        _handleGlobalRequestHostkey(message);
        handled = true;
        break;
      default:
        printDebug?.call(
            'Received unhandled global request "${message.requestName}".');
        break;
    }

    if (!handled && message.wantReply) {
      _sendMessage(SSH_Message_Request_Failure());
    }
  }

  void _handleGlobalRequestHostkey(SSH_Message_Global_Request request) {
    printDebug?.call('SSHClient._handleGlobalRequestHostkey');
    if (onHostKeys != null) {
      // This assumes that SSH_Message_Global_Request.decode correctly populates
      // request.hostKeys and that the hostKeys field (List<SSHHostKey>?)
      // is available in the SSH_Message_Global_Request class from msg_request.dart.
      if (request.hostKeys != null && request.hostKeys!.isNotEmpty) {
        onHostKeys!(request.hostKeys!);
      } else {
        printDebug?.call(
            'Received hostkeys-00@openssh.com request with no host keys or hostKeys field not populated.');
      }
    } else {
      printDebug?.call(
          'Received hostkeys-00@openssh.com but no onHostKeys handler is set.');
    }
    // hostkeys-00@openssh.com global request has wantReply=false,
    // so no SSH_Message_Request_Success or Failure is sent.
  }

  void _handleGlobalRequestSuccess(Uint8List payload) {
    final message = SSH_Message_Request_Success.decode(payload);
    printTrace?.call('<- $socket: $message');
    _globalRequestReplyQueue.add(message);
  }

  void _handleGlobalRequestFailure(Uint8List payload) {
    final message = SSH_Message_Request_Failure.decode(payload);
    printTrace?.call('<- $socket: $message');
    _globalRequestReplyQueue.add(message);
  }

  void _handleChannelOpen(Uint8List payload) {
    final message = SSH_Message_Channel_Open.decode(payload);
    printTrace?.call('<- $socket: $message');

    switch (message.channelType) {
      case 'forwarded-tcpip':
        return _handleForwardedTcpipChannelOpen(message);
      case 'x11':
        return _handleX11ChannelOpen(message);
      case 'auth-agent@openssh.com':
        return _handleAgentChannelOpen(message);
    }

    printDebug?.call('unknown channelType: ${message.channelType}');
    final reply = SSH_Message_Channel_Open_Failure(
      recipientChannel: message.senderChannel,
      reasonCode: SSH_Message_Channel_Open_Failure.codeUnknownChannelType,
      description: 'unknown channel type: ${message.channelType}',
    );
    _sendMessage(reply);
  }

  void _handleForwardedTcpipChannelOpen(SSH_Message_Channel_Open message) {
    printDebug?.call('SSHClient._handleTcpipForwardChannelOpen');

    final remoteForward = _findRemoteForward(message.host!, message.port!);

    if (remoteForward == null) {
      printDebug?.call('unknown remote forward: $message');
      final reply = SSH_Message_Channel_Open_Failure(
        recipientChannel: message.senderChannel,
        reasonCode: SSH_Message_Channel_Open_Failure.codeUnknownChannelType,
        description: 'unknown remote forward: $message',
      );
      _sendMessage(reply);
      return;
    }

    if (remoteForward.filter != null) {
      if (!remoteForward.filter!(message.host!, message.port!)) {
        printDebug?.call('remote forward rejected by filter: $message');
        final reply = SSH_Message_Channel_Open_Failure(
          recipientChannel: message.senderChannel,
          reasonCode: 1, // SSH_OPEN_ADMINISTRATIVELY_PROHIBITED
          description: 'rejected by filter',
        );
        _sendMessage(reply);
        return;
      }
    }

    final localChannelId = _channelIdAllocator.allocate();

    final confirmation = SSH_Message_Channel_Confirmation(
      recipientChannel: message.senderChannel,
      senderChannel: localChannelId,
      initialWindowSize: _initialWindowSize,
      maximumPacketSize: _maximumPacketSize,
      data: Uint8List(0),
    );

    _sendMessage(confirmation);

    final channelController = _acceptChannel(
      localChannelId: localChannelId,
      remoteChannelId: message.senderChannel,
      remoteInitialWindowSize: message.initialWindowSize,
      remoteMaximumPacketSize: message.maximumPacketSize,
    );

    remoteForward._connections.add(
      SSHForwardChannel(channelController.channel),
    );
  }

  void _handleX11ChannelOpen(SSH_Message_Channel_Open message) {
    printDebug?.call('SSHClient._handleX11ChannelOpen');

    if (onX11Forward == null) {
      final reply = SSH_Message_Channel_Open_Failure(
        recipientChannel: message.senderChannel,
        reasonCode: 1, // SSH_OPEN_ADMINISTRATIVELY_PROHIBITED
        description: 'x11 forwarding not enabled',
      );
      _sendMessage(reply);
      return;
    }

    final localChannelId = _channelIdAllocator.allocate();

    final confirmation = SSH_Message_Channel_Confirmation(
      recipientChannel: message.senderChannel,
      senderChannel: localChannelId,
      initialWindowSize: _initialWindowSize,
      maximumPacketSize: _maximumPacketSize,
      data: Uint8List(0),
    );

    _sendMessage(confirmation);

    final channelController = _acceptChannel(
      localChannelId: localChannelId,
      remoteChannelId: message.senderChannel,
      remoteInitialWindowSize: message.initialWindowSize,
      remoteMaximumPacketSize: message.maximumPacketSize,
    );

    onX11Forward!(
      SSHX11Channel(
        channelController.channel,
        originatorIP: message.originatorIP ?? '',
        originatorPort: message.originatorPort ?? 0,
      ),
    );
  }

  void _handleAgentChannelOpen(SSH_Message_Channel_Open message) {
    final handler = agentHandler;
    if (handler == null) {
      final reply = SSH_Message_Channel_Open_Failure(
        recipientChannel: message.senderChannel,
        reasonCode:
            SSH_Message_Channel_Open_Failure.codeAdministrativelyProhibited,
        description: 'agent forwarding not enabled',
      );
      _sendMessage(reply);
      return;
    }

    final localChannelId = _channelIdAllocator.allocate();
    final confirmation = SSH_Message_Channel_Confirmation(
      recipientChannel: message.senderChannel,
      senderChannel: localChannelId,
      initialWindowSize: _initialWindowSize,
      maximumPacketSize: _maximumPacketSize,
      data: Uint8List(0),
    );
    _sendMessage(confirmation);

    final channelController = _acceptChannel(
      localChannelId: localChannelId,
      remoteChannelId: message.senderChannel,
      remoteInitialWindowSize: message.initialWindowSize,
      remoteMaximumPacketSize: message.maximumPacketSize,
    );

    SSHAgentChannel(
      channelController.channel,
      handler,
      printDebug: printDebug,
    );
  }

  /// Finds a remote forward that matches the given host and port.
  SSHRemoteForward? _findRemoteForward(String host, int port) {
    final result = _remoteForwards.where(
      (forward) => forward.host == host && forward.port == port,
    );
    return result.isEmpty ? null : result.first;
  }

  void _handleChannelConfirmation(Uint8List payload) {
    final message = SSH_Message_Channel_Confirmation.decode(payload);
    printTrace?.call('<- $socket: $message');
    if (!_channelOpenReplyWaiters.containsKey(message.recipientChannel)) {
      printDebug?.call(
          '_handleChannelConfirmation: no pending open for local channel ${message.recipientChannel}, discarding');
      return;
    }
    if (_channels.containsKey(message.recipientChannel)) {
      printDebug?.call(
          '_handleChannelConfirmation: channel ${message.recipientChannel} already closed, discarding');
      return;
    }
    _acceptChannel(
      localChannelId: message.recipientChannel,
      remoteChannelId: message.senderChannel,
      remoteInitialWindowSize: message.initialWindowSize,
      remoteMaximumPacketSize: message.maximumPacketSize,
    );
    _dispatchChannelOpenReply(message.recipientChannel, message);
  }

  void _handleChannelOpenFailure(Uint8List payload) {
    final message = SSH_Message_Channel_Open_Failure.decode(payload);
    printTrace?.call('<- $socket: $message');
    _dispatchChannelOpenReply(message.recipientChannel, message);
  }

  void _handleChannelWindowAdjust(Uint8List payload) {
    final message = SSH_Message_Channel_Window_Adjust.decode(payload);
    printTrace?.call('<- $socket: $message');
    _channels[message.recipientChannel]?.handleMessage(message);
  }

  void _handleChannelRequest(Uint8List payload) {
    final message = SSH_Message_Channel_Request.decode(payload);
    printTrace?.call('<- $socket: $message');
    _channels[message.recipientChannel]?.handleMessage(message);
  }

  void _handleChannelSuccess(Uint8List payload) {
    final message = SSH_Message_Channel_Success.decode(payload);
    printTrace?.call('<- $socket: $message');
    _channels[message.recipientChannel]?.handleMessage(message);
  }

  void _handleChannelFailure(Uint8List payload) {
    final message = SSH_Message_Channel_Failure.decode(payload);
    printTrace?.call('<- $socket: $message');
    _channels[message.recipientChannel]?.handleMessage(message);
  }

  void _handleChannelData(Uint8List payload) {
    final message = SSH_Message_Channel_Data.decode(payload);
    printTrace?.call('<- $socket: $message');
    _channels[message.recipientChannel]?.handleMessage(message);
  }

  void _handleChannelExtendedData(Uint8List payload) {
    final message = SSH_Message_Channel_Extended_Data.decode(payload);
    printTrace?.call('<- $socket: $message');
    _channels[message.recipientChannel]?.handleMessage(message);
  }

  void _handleChannelEOF(Uint8List payload) {
    final message = SSH_Message_Channel_EOF.decode(payload);
    printTrace?.call('<- $socket: $message');
    _channels[message.recipientChannel]?.handleMessage(message);
  }

  void _handleChannelClose(Uint8List payload) {
    final message = SSH_Message_Channel_Close.decode(payload);
    printTrace?.call('<- $socket: $message');
    final channel = _channels[message.recipientChannel];
    if (channel != null) {
      channel.handleMessage(message);
      _channels.remove(message.recipientChannel);
      _channelIdAllocator.release(message.recipientChannel);
    }
  }

  void _requestAuthentication() {
    printDebug?.call('SSHClient._requestAuthentication');
    _sendMessage(SSH_Message_Service_Request('ssh-userauth'));
  }

  void _startAuthentication() {
    printDebug?.call('SSHClient._startAuthentication');

    // RFC 4252: Check transport layer security before enabling password auth
    final hasConfidentiality = _hasConfidentiality;
    final hasMac = _hasMacProtection;

    printDebug
        ?.call('Transport confidentiality: $hasConfidentiality, MAC: $hasMac');

    // RFC 4252: First try "none" method to get list of supported methods
    _authMethodsLeft.add(SSHAuthMethod.none);

    if (identities != null && identities!.isNotEmpty) {
      _authMethodsLeft.add(SSHAuthMethod.publicKey);
    }

    // RFC 4252: Password authentication should be disabled if no confidentiality
    if (onPasswordRequest != null) {
      if (!hasConfidentiality) {
        printDebug?.call(
            'WARNING: Password authentication disabled - no transport confidentiality (RFC 4252)');
      } else {
        _authMethodsLeft.add(SSHAuthMethod.password);
      }
    }

    if (onUserInfoRequest != null) {
      _authMethodsLeft.add(SSHAuthMethod.keyboardInteractive);
    }

    if (hostbasedIdentities != null &&
        hostbasedIdentities!.isNotEmpty &&
        hostName != null &&
        userNameOnClientHost != null) {
      _authMethodsLeft.add(SSHAuthMethod.hostbased);
    }

    _tryNextAuthMethod();
  }

  void _tryNextAuthMethod() {
    printDebug?.call('SSHClient._tryNextAuthenticationMethod');

    if (_authAttempts >= maxAuthAttempts) {
      _authenticated.completeError(
        SSHAuthAbortError('Reached max attempts($maxAuthAttempts)'),
      );
      close();
      return;
    }

    if (_currentAuthMethod == SSHAuthMethod.publicKey) {
      if (_keyPairsLeft.isNotEmpty) {
        return _authWithNextPublicKey();
      }
    }

    if (_authMethodsLeft.isEmpty) {
      final triedMethods = [
        if (_currentAuthMethod != null) _currentAuthMethod!.name,
        ...SSHAuthMethod.values
            .where((m) => m != SSHAuthMethod.none && m != _currentAuthMethod)
            .map((m) => m.name)
      ].join(', ');

      return _authenticated.completeError(
        SSHAuthFailError(
            'All authentication methods failed. Tried: $triedMethods'),
        StackTrace.current,
      );
    }

    _currentAuthMethod = _authMethodsLeft.removeFirst();
    printDebug?.call('_currentAuthMethod = $_currentAuthMethod');

    switch (_currentAuthMethod!) {
      case SSHAuthMethod.none:
        return _authWithNone();
      case SSHAuthMethod.password:
        return _catch(() => _authWithPassword());
      case SSHAuthMethod.publicKey:
        return _authWithNextPublicKey();
      case SSHAuthMethod.keyboardInteractive:
        return _authWithKeyboardInteractive();
      case SSHAuthMethod.hostbased:
        return _authWithNextHostbased();
    }
  }

  void _authWithNone() {
    printDebug?.call('SSHClient._authWithNone');
    _authAttempts++;

    // RFC 4252: The main purpose of sending "none" is to get the list
    // of supported methods from the server
    printDebug
        ?.call('Sending "none" authentication to discover supported methods');
    _sendMessage(SSH_Message_Userauth_Request.none(user: username));
  }

  Future<void> _authWithPassword() async {
    printDebug?.call('SSHClient._authWithPassword');

    // RFC 4252: Check confidentiality before sending password
    if (!_hasConfidentiality) {
      printDebug?.call(
          'Refusing password authentication - no transport confidentiality');
      _tryNextAuthMethod();
      return;
    }

    _authAttempts++;

    final password = await onPasswordRequest!();
    if (password == null) {
      _tryNextAuthMethod();
      return;
    }

    _sendMessage(
      SSH_Message_Userauth_Request.password(user: username, password: password),
    );
  }

  void _authWithNextPublicKey() {
    printDebug?.call('SSHClient._authWithPublicKey');
    _authAttempts++;

    final keyPair = _keyPairsLeft.removeFirst();

    final challenge = _transport.composeChallenge(
      username: username,
      service: 'ssh-connection',
      publicKeyAlgorithm: keyPair.type,
      publicKey: keyPair.toPublicKey().encode(),
    );

    _sendMessage(
      SSH_Message_Userauth_Request.publicKey(
        username: username,
        publicKeyAlgorithm: keyPair.type,
        publicKey: keyPair.toPublicKey().encode(),
        signature: keyPair.sign(challenge).encode(),
        // signature: null,
      ),
    );
  }

  void _authWithKeyboardInteractive() {
    printDebug?.call('SSHClient._authWithKeyboardInteractive');
    _authAttempts++;
    _sendMessage(
      SSH_Message_Userauth_Request.keyboardInteractive(user: username),
    );
  }

  void _authWithNextHostbased() {
    printDebug?.call('SSHClient._authWithHostbased');
    _authAttempts++;

    if (_hostbasedKeyPairsLeft.isEmpty) {
      _tryNextAuthMethod();
      return;
    }

    final keyPair = _hostbasedKeyPairsLeft.removeFirst();

    if (hostName == null || userNameOnClientHost == null) {
      printDebug
          ?.call('SSHClient._authWithHostbased: missing hostname or username');
      _tryNextAuthMethod();
      return;
    }

    try {
      final challenge = _transport.composeHostbasedChallenge(
        username: username,
        service: 'ssh-connection',
        publicKeyAlgorithm: keyPair.type,
        publicKey: keyPair.toPublicKey().encode(),
        hostName: hostName!,
        userNameOnClientHost: userNameOnClientHost!,
      );

      final signature = keyPair.sign(challenge);

      printDebug?.call('Attempting hostbased auth with ${keyPair.type}');

      _sendMessage(
        SSH_Message_Userauth_Request.hostbased(
          username: username,
          publicKeyAlgorithm: keyPair.type,
          publicKey: keyPair.toPublicKey().encode(),
          hostName: hostName!,
          userNameOnClientHost: userNameOnClientHost!,
          signature: signature.encode(),
        ),
      );
    } catch (e, stack) {
      printDebug?.call('SSHClient._authWithHostbased: error: $e\n$stack');
      if (_hostbasedKeyPairsLeft.isEmpty) {
        _tryNextAuthMethod();
      } else {
        _authWithNextHostbased();
      }
    }
  }

  /// Updates the authentication method queue based on server's response
  void _updateAuthMethodsBasedOnServerResponse(
      List<String> serverMethods, bool partialSuccess) {
    // RFC 4252: Server tells us which methods may productively continue
    final supportedMethods = <SSHAuthMethod>[];

    // Map server method names to our enum values
    for (final methodName in serverMethods) {
      switch (methodName) {
        case 'publickey':
          if (identities != null && identities!.isNotEmpty) {
            supportedMethods.add(SSHAuthMethod.publicKey);
          }
          break;
        case 'password':
          if (onPasswordRequest != null) {
            supportedMethods.add(SSHAuthMethod.password);
          }
          break;
        case 'keyboard-interactive':
          if (onUserInfoRequest != null) {
            supportedMethods.add(SSHAuthMethod.keyboardInteractive);
          }
          break;
        case 'hostbased':
          if (hostbasedIdentities != null &&
              hostbasedIdentities!.isNotEmpty &&
              hostName != null &&
              userNameOnClientHost != null) {
            supportedMethods.add(SSHAuthMethod.hostbased);
          }
          break;
        case 'none':
          // RFC 4252: "none" should not be listed as supported, but handle it
          printDebug?.call('Warning: Server listed "none" as supported method');
          break;
        default:
          printDebug
              ?.call('Unknown authentication method from server: $methodName');
      }
    }

    // Update our method queue to only include server-supported methods
    _authMethodsLeft.clear();
    _authMethodsLeft.addAll(supportedMethods);

    if (partialSuccess) {
      printDebug?.call(
          'Partial authentication success - continuing with additional methods');
    }

    if (_authMethodsLeft.isEmpty) {
      printDebug
          ?.call('No mutually supported authentication methods available');
    }
  }

  Future<SSHChannelController> _openSessionChannel() async {
    final localChannelId = _channelIdAllocator.allocate();

    final request = SSH_Message_Channel_Open.session(
      senderChannel: localChannelId,
      initialWindowSize: _initialWindowSize,
      maximumPacketSize: _maximumPacketSize,
    );
    _sendMessage(request);

    return await _waitChannelOpen(localChannelId);
  }

  Future<SSHChannelController> _openForwardLocalChannel(
    String bindAddress,
    int bindPort,
    String remoteAddress,
    int remotePort,
  ) async {
    final localChannelId = _channelIdAllocator.allocate();

    final request = SSH_Message_Channel_Open.directTcpip(
      senderChannel: localChannelId,
      initialWindowSize: _initialWindowSize,
      maximumPacketSize: _maximumPacketSize,
      host: remoteAddress,
      port: remotePort,
      originatorIP: bindAddress,
      originatorPort: bindPort,
    );
    _sendMessage(request);

    return await _waitChannelOpen(localChannelId);
  }

  Future<SSHChannelController> _openForwardLocalUnixChannel(
    String socketPath,
  ) async {
    final localChannelId = _channelIdAllocator.allocate();

    final request = SSH_Message_Channel_Open.directStreamLocal(
      senderChannel: localChannelId,
      initialWindowSize: _initialWindowSize,
      maximumPacketSize: _maximumPacketSize,
      socketPath: socketPath,
    );
    _sendMessage(request);

    return await _waitChannelOpen(localChannelId);
  }

  Future<SSHChannelController> _waitChannelOpen(
    SSHChannelId localChannelId,
  ) async {
    final message = await _waitChannelOpenReply(localChannelId);
    if (message is SSH_Message_Channel_Open_Failure) {
      throw SSHChannelOpenError(message.reasonCode, message.description);
    }

    final controller = _channels[localChannelId];
    if (controller == null) {
      throw SSHStateError(
          'Channel $localChannelId was closed before channel-open completed');
    }
    return controller;
  }

  SSHChannelController _acceptChannel({
    required SSHChannelId localChannelId,
    required SSHChannelId remoteChannelId,
    required int remoteInitialWindowSize,
    required int remoteMaximumPacketSize,
  }) {
    final channelController = SSHChannelController(
      localId: localChannelId,
      localInitialWindowSize: _initialWindowSize,
      localMaximumPacketSize: _maximumPacketSize,
      remoteId: remoteChannelId,
      remoteInitialWindowSize: remoteInitialWindowSize,
      remoteMaximumPacketSize: remoteMaximumPacketSize,
      sendMessage: _sendMessage,
      printDebug: printDebug,
    );

    _channels[localChannelId] = channelController;
    return channelController;
  }

  Future<SSHMessage> _waitChannelOpenReply(SSHChannelId id) async {
    final waiter = _channelOpenReplyWaiters[id];
    if (waiter != null) {
      printDebug?.call('_waitChannelOpenReply: already waiting for $id');
      return waiter.future;
    }
    final replyCompleter = Completer<SSHMessage>();
    _channelOpenReplyWaiters[id] = replyCompleter;
    return replyCompleter.future;
  }

  void _dispatchChannelOpenReply(SSHChannelId id, SSHMessage message) {
    if (!_channelOpenReplyWaiters.containsKey(id)) {
      printDebug?.call('_dispatchChannelOpenReply: no pending request for $id');
      return;
    }
    final replyCompleter = _channelOpenReplyWaiters.remove(id)!;
    replyCompleter.complete(message);
  }

  void _onAuthTimeout() {
    if (!_authenticated.isCompleted) {
      final attemptedMethods = <String>[];

      if (_currentAuthMethod != null) {
        attemptedMethods.add(_currentAuthMethod!.name);
      }

      var timeoutMessage =
          'Authentication timed out after ${authTimeout.inSeconds} seconds.';

      if (_authAttempts > 0) {
        timeoutMessage += ' Made $_authAttempts authentication attempts.';

        if (attemptedMethods.isNotEmpty) {
          timeoutMessage += ' Methods tried: ${attemptedMethods.join(', ')}';
        }
      } else {
        timeoutMessage += ' No authentication attempts were made.';
      }

      _authenticated.completeError(SSHAuthAbortError(timeoutMessage));
      close();
    }
  }
}

extension on SSHClient {
  /// Check if the transport layer provides confidentiality (encryption)
  bool get _hasConfidentiality {
    // Check if current cipher provides confidentiality
    // This would need to be implemented in SSHTransport to expose current cipher info
    return _transport.hasConfidentiality;
  }

  /// Check if the transport layer provides MAC protection
  bool get _hasMacProtection {
    return _transport.hasMacProtection;
  }
}

extension on SSHClient {
  /// Sanitize banner message according to RFC 4252 recommendations
  ///
  /// This method filters control characters to prevent terminal control
  /// character attacks as recommended by RFC 4252.
  String _sanitizeBannerMessage(String message) {
    final buffer = StringBuffer();
    var lineLength = 0;
    const maxLineLength = 1024; // Reasonable limit to prevent DoS
    var totalLength = 0;
    const maxTotalLength = 8192; // Total message size limit

    for (int i = 0; i < message.length && totalLength < maxTotalLength; i++) {
      final code = message.codeUnitAt(i);

      // RFC 4252: Allow specific control characters
      if (code == 9) {
        // TAB
        buffer.writeCharCode(code);
        lineLength += 4; // Count as 4 chars for line length
        totalLength++;
      } else if (code == 10) {
        // LF (Line Feed)
        buffer.writeCharCode(code);
        lineLength = 0; // Reset line length
        totalLength++;
      } else if (code == 13) {
        // CR (Carriage Return)
        buffer.writeCharCode(code);
        // Don't reset line length for CR, might be part of CRLF
        totalLength++;
      } else if (code >= 32 && code <= 126) {
        // Printable ASCII
        if (lineLength < maxLineLength) {
          buffer.writeCharCode(code);
          lineLength++;
        }
        totalLength++;
      } else if (code > 127) {
        // Non-ASCII (UTF-8)
        // Allow valid UTF-8 characters but be careful with length
        if (lineLength < maxLineLength) {
          buffer.writeCharCode(code);
          lineLength++;
        }
        totalLength++;
      } else {
        // RFC 4252: Filter out other control characters
        // Replace with escaped representation for debugging
        final escaped = '\\x${code.toRadixString(16).padLeft(2, '0')}';
        if (lineLength + escaped.length < maxLineLength) {
          buffer.write(escaped);
          lineLength += escaped.length;
        }
        totalLength += escaped.length;
      }

      // Prevent excessively long lines
      if (lineLength >= maxLineLength) {
        buffer.writeln(''); // Force line break
        lineLength = 0;
      }
    }

    final result = buffer.toString();

    // Log if message was truncated
    if (totalLength >= maxTotalLength) {
      printDebug?.call(
          'Banner message truncated at $maxTotalLength characters for security');
    }

    return result;
  }
}

class SSHRemoteForward {
  final String host;

  final int port;

  final SSHRemoteConnectionFilter? filter;

  SSHRemoteForward(this._client, this.host, this.port, this.filter);

  final SSHClient _client;

  final _connections = StreamController<SSHForwardChannel>();

  Stream<SSHForwardChannel> get connections => _connections.stream;

  void close() {
    _connections.close();
    _client.cancelForwardRemote(this);
  }

  @override
  String toString() => '$runtimeType($host:$port)';
}
