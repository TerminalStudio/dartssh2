import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/src/ssh_channel.dart';

class SSHForwardChannel {
  final SSHChannel _channel;

  SSHForwardChannel(this._channel) {
    _sinkController.stream
        .map((data) => SSHChannelData(data))
        .pipe(_channel.sink);
  }

  final _sinkController = StreamController<Uint8List>();

  /// Data received from the remote host.
  Stream<Uint8List> get stream => _channel.stream.map((data) => data.bytes);

  /// Write to this sink to send data to the remote host.
  StreamSink<Uint8List> get sink => _sinkController.sink;

  /// Close the forward channel.
  void close() => _channel.close();

  /// A future that completes when the channel is closed.
  Future<void> get done => _channel.done;
}
