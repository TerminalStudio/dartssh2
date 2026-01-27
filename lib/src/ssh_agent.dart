import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/src/ssh_channel.dart';
import 'package:dartssh2/src/ssh_key_pair.dart';
import 'package:dartssh2/src/ssh_message.dart';
import 'package:dartssh2/src/ssh_transport.dart';

abstract class SSHAgentHandler {
  Future<Uint8List> handleRequest(Uint8List request);
}

class SSHKeyPairAgent implements SSHAgentHandler {
  SSHKeyPairAgent(this._identities, {this.comment});

  final List<SSHKeyPair> _identities;
  final String? comment;

  @override
  Future<Uint8List> handleRequest(Uint8List request) async {
    if (request.isEmpty) {
      return _failure();
    }
    final reader = SSHMessageReader(request);
    final messageType = reader.readUint8();
    switch (messageType) {
      case SSHAgentProtocol.requestIdentities:
        return _handleRequestIdentities();
      case SSHAgentProtocol.signRequest:
        return _handleSignRequest(reader);
      default:
        return _failure();
    }
  }

  Uint8List _handleRequestIdentities() {
    final writer = SSHMessageWriter();
    writer.writeUint8(SSHAgentProtocol.identitiesAnswer);
    writer.writeUint32(_identities.length);
    for (final identity in _identities) {
      final publicKey = identity.toPublicKey().encode();
      writer.writeString(publicKey);
      writer.writeUtf8(comment ?? '');
    }
    return writer.takeBytes();
  }

  Uint8List _handleSignRequest(SSHMessageReader reader) {
    final keyBlob = reader.readString();
    final data = reader.readString();
    reader.readUint32(); // flags, ignored for now

    final identity = _findIdentity(keyBlob);
    if (identity == null) {
      return _failure();
    }

    final signature = identity.sign(data);
    final writer = SSHMessageWriter();
    writer.writeUint8(SSHAgentProtocol.signResponse);
    writer.writeString(signature.encode());
    return writer.takeBytes();
  }

  SSHKeyPair? _findIdentity(Uint8List keyBlob) {
    for (final identity in _identities) {
      final publicKey = identity.toPublicKey().encode();
      if (_bytesEqual(publicKey, keyBlob)) {
        return identity;
      }
    }
    return null;
  }

  Uint8List _failure() {
    final writer = SSHMessageWriter();
    writer.writeUint8(SSHAgentProtocol.failure);
    return writer.takeBytes();
  }

  bool _bytesEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

class SSHAgentChannel {
  SSHAgentChannel(this._channel, this._handler, {this.printDebug}) {
    _subscription = _channel.stream.listen(
      _handleData,
      onDone: _handleDone,
      onError: (_, __) => _handleDone(),
    );
  }

  final SSHChannel _channel;
  final SSHAgentHandler _handler;
  final SSHPrintHandler? printDebug;

  StreamSubscription<SSHChannelData>? _subscription;
  Uint8List _buffer = Uint8List(0);
  bool _processing = false;

  void _handleDone() {
    _subscription?.cancel();
  }

  void _handleData(SSHChannelData data) {
    _buffer = _appendBytes(_buffer, data.bytes);
    _drainRequests();
  }

  void _drainRequests() {
    if (_processing) return;
    _processing = true;
    _processQueue().whenComplete(() => _processing = false);
  }

  Future<void> _processQueue() async {
    while (_buffer.length >= 4) {
      final length = ByteData.sublistView(_buffer, 0, 4).getUint32(0);
      if (_buffer.length < 4 + length) return;
      final payload = _buffer.sublist(4, 4 + length);
      _buffer = _buffer.sublist(4 + length);
      Uint8List response;
      try {
        response = await _handler.handleRequest(payload);
      } catch (error) {
        printDebug?.call('SSH agent handler error: $error');
        response = _failureResponse();
      }
      _sendResponse(response);
    }
  }

  Uint8List _failureResponse() {
    final writer = SSHMessageWriter();
    writer.writeUint8(SSHAgentProtocol.failure);
    return writer.takeBytes();
  }

  void _sendResponse(Uint8List payload) {
    final writer = SSHMessageWriter();
    writer.writeUint32(payload.length);
    writer.writeBytes(payload);
    _channel.addData(writer.takeBytes());
  }

  Uint8List _appendBytes(Uint8List a, Uint8List b) {
    if (a.isEmpty) return b;
    if (b.isEmpty) return a;
    final combined = Uint8List(a.length + b.length);
    combined.setAll(0, a);
    combined.setAll(a.length, b);
    return combined;
  }
}

abstract class SSHAgentProtocol {
  static const int failure = 5;
  static const int requestIdentities = 11;
  static const int identitiesAnswer = 12;
  static const int signRequest = 13;
  static const int signResponse = 14;
}
