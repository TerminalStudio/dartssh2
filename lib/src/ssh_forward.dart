import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/src/socket/ssh_socket.dart';
import 'package:dartssh2/src/ssh_channel.dart';

class SSHForwardChannel implements SSHSocket {
  final SSHChannel _channel;

  SSHForwardChannel(this._channel) {
    _sinkController.stream
        .map((data) => SSHChannelData(data))
        .pipe(_channel.sink);
  }

  final _sinkController = StreamController<Uint8List>();

  /// Data received from the remote host.
  @override
  Stream<Uint8List> get stream => _channel.stream.map((data) => data.bytes);

  /// Write to this sink to send data to the remote host.
  @override
  StreamSink<Uint8List> get sink => _sinkController.sink;

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
