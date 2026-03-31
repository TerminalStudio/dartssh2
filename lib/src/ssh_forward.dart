import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/src/socket/ssh_socket.dart';
import 'package:dartssh2/src/ssh_channel.dart';

/// Filters outbound targets requested through a dynamic forward (SOCKS proxy).
///
/// Return `true` to allow connecting to `[host]:[port]`, `false` to deny.
typedef SSHDynamicConnectionFilter = bool Function(String host, int port);

/// Configuration for [SSHClient.forwardDynamic].
class SSHDynamicForwardOptions {
  /// Maximum time allowed to complete the SOCKS5 handshake and target request.
  final Duration handshakeTimeout;

  /// Maximum time allowed to establish the SSH forwarded connection to target.
  final Duration connectTimeout;

  /// Maximum number of simultaneous SOCKS client connections.
  final int maxConnections;

  const SSHDynamicForwardOptions({
    this.handshakeTimeout = const Duration(seconds: 10),
    this.connectTimeout = const Duration(seconds: 15),
    this.maxConnections = 128,
  }) : assert(maxConnections > 0, 'maxConnections must be greater than zero');
}

/// A local dynamic forwarding server (SOCKS5 CONNECT) managed by [SSHClient].
abstract class SSHDynamicForward {
  /// Host/interface the local SOCKS server is bound to.
  String get host;

  /// Bound local port of the SOCKS server.
  int get port;

  /// Whether this forwarder has already been closed.
  bool get isClosed;

  /// Stops accepting new SOCKS connections and closes active ones.
  Future<void> close();
}

class SSHForwardChannel implements SSHSocket {
  final SSHChannel _channel;

  SSHForwardChannel(this._channel) {
    _sinkController.stream
        .map((data) => data is Uint8List ? data : Uint8List.fromList(data))
        .map((data) => SSHChannelData(data))
        .pipe(_channel.sink);
  }

  final _sinkController = StreamController<List<int>>();

  /// Data received from the remote host.
  @override
  Stream<Uint8List> get stream => _channel.stream.map((data) => data.bytes);

  /// Write to this sink to send data to the remote host.
  @override
  StreamSink<List<int>> get sink => _sinkController.sink;

  /// Close our end of the channel. Returns a future that waits for the
  /// other side to close.
  @override
  Future<void> close() => _channel.close();

  /// A future that completes when both ends of the channel are closed.
  @override
  Future<void> get done => _channel.done;

  /// Destroys the socket in both directions.
  @override
  void destroy() {
    _channel.destroy();
  }
}

class SSHX11Channel extends SSHForwardChannel {
  /// Originator address reported by the SSH server for this X11 channel.
  final String originatorIP;

  /// Originator port reported by the SSH server for this X11 channel.
  final int originatorPort;

  SSHX11Channel(
    super.channel, {
    required this.originatorIP,
    required this.originatorPort,
  });
}
