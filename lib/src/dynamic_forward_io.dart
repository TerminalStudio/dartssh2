import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dartssh2/src/ssh_forward.dart';

typedef SSHDynamicDial = Future<SSHForwardChannel> Function(
  String host,
  int port,
);

Future<SSHDynamicForward> startDynamicForward({
  required String bindHost,
  required int? bindPort,
  required SSHDynamicForwardOptions options,
  SSHDynamicConnectionFilter? filter,
  required SSHDynamicDial dial,
}) async {
  final server = await ServerSocket.bind(bindHost, bindPort ?? 0);
  return _SSHDynamicForwardImpl(
    server,
    options: options,
    filter: filter,
    dial: dial,
  );
}

class _SSHDynamicForwardImpl implements SSHDynamicForward {
  _SSHDynamicForwardImpl(
    this._server, {
    required this.options,
    required this.filter,
    required this.dial,
  }) {
    _serverSub = _server.listen(_handleClient);
  }

  final ServerSocket _server;
  final SSHDynamicForwardOptions options;
  final SSHDynamicConnectionFilter? filter;
  final SSHDynamicDial dial;
  late final StreamSubscription<Socket> _serverSub;
  final _connections = <_SocksConnection>{};
  bool _closed = false;

  @override
  String get host => _server.address.host;

  @override
  int get port => _server.port;

  @override
  bool get isClosed => _closed;

  void _handleClient(Socket client) {
    if (_closed) {
      client.destroy();
      return;
    }

    late final _SocksConnection connection;
    connection = _SocksConnection(
      client,
      options: options,
      filter: filter,
      canOpenTunnel: () => _connections.length < options.maxConnections,
      dial: dial,
      onClosed: () => _connections.remove(connection),
    );

    _connections.add(connection);
    connection.start();
  }

  @override
  Future<void> close() async {
    if (_closed) return;
    _closed = true;

    await _serverSub.cancel();
    await _server.close();

    final closes =
        _connections.map((connection) => connection.close()).toList();
    await Future.wait(closes);
    _connections.clear();
  }
}

class _SocksConnection {
  _SocksConnection(
    this._client, {
    required this.options,
    required this.filter,
    required this.canOpenTunnel,
    required this.dial,
    required this.onClosed,
  });

  static const _socksVersion = 0x05;

  final Socket _client;
  final SSHDynamicForwardOptions options;
  final SSHDynamicConnectionFilter? filter;
  final bool Function() canOpenTunnel;
  final SSHDynamicDial dial;
  final void Function() onClosed;

  final _buffer = _ByteBuffer();

  SSHForwardChannel? _remote;
  StreamSubscription<List<int>>? _clientSub;
  StreamSubscription<Uint8List>? _remoteSub;
  Timer? _handshakeTimer;
  bool _closed = false;
  _SocksState _state = _SocksState.greeting;

  void start() {
    _clientSub = _client.listen(
      _onClientData,
      onDone: close,
      onError: (_, __) => close(),
      cancelOnError: true,
    );

    _handshakeTimer = Timer(options.handshakeTimeout, () async {
      _sendReply(_SocksReply.ttlExpired);
      await close();
    });
  }

  Future<void> close() async {
    if (_closed) return;
    _closed = true;

    await _clientSub?.cancel();
    await _remoteSub?.cancel();
    _handshakeTimer?.cancel();

    _remote?.destroy();
    _client.destroy();

    onClosed();
  }

  Future<void> _onClientData(List<int> chunk) async {
    if (_closed) return;

    if (_state == _SocksState.streaming) {
      _remote?.sink.add(chunk);
      return;
    }

    _buffer.add(chunk);

    try {
      await _consumeHandshake();
    } catch (_) {
      await close();
    }
  }

  Future<void> _consumeHandshake() async {
    if (_state == _SocksState.greeting) {
      final parsed = _parseGreeting();
      if (!parsed) return;
      _state = _SocksState.request;
    }

    if (_state == _SocksState.request) {
      final target = _parseConnectRequest();
      if (target == null) return;

      if (filter != null && !filter!(target.host, target.port)) {
        _sendReply(_SocksReply.connectionNotAllowed);
        await close();
        return;
      }

      if (!canOpenTunnel()) {
        _sendReply(_SocksReply.connectionRefused);
        await close();
        return;
      }

      try {
        _remote = await dial(target.host, target.port).timeout(
          options.connectTimeout,
        );
      } catch (_) {
        _sendReply(_SocksReply.hostUnreachable);
        await close();
        return;
      }

      if (_closed) {
        _remote?.destroy();
        _remote = null;
        return;
      }

      _remoteSub = _remote!.stream.listen(
        _client.add,
        onDone: close,
        onError: (_, __) => close(),
        cancelOnError: true,
      );

      _sendReply(_SocksReply.succeeded);
      _handshakeTimer?.cancel();
      _handshakeTimer = null;
      _state = _SocksState.streaming;

      final pending = _buffer.takeAll();
      if (pending.isNotEmpty) {
        _remote!.sink.add(pending);
      }
    }
  }

  bool _parseGreeting() {
    if (_buffer.length < 2) return false;

    final version = _buffer.peek(0);
    final methodsCount = _buffer.peek(1);
    final totalLength = 2 + methodsCount;

    if (_buffer.length < totalLength) return false;

    final payload = _buffer.read(totalLength);

    if (version != _socksVersion) {
      _sendMethodSelection(0xFF);
      throw StateError('Unsupported SOCKS version');
    }

    final methods = payload.sublist(2);
    if (methods.contains(0x00)) {
      _sendMethodSelection(0x00);
    } else {
      _sendMethodSelection(0xFF);
      throw StateError('No supported authentication method');
    }

    return true;
  }

  _TargetAddress? _parseConnectRequest() {
    if (_buffer.length < 4) return null;

    final version = _buffer.peek(0);
    final command = _buffer.peek(1);
    final atyp = _buffer.peek(3);

    if (version != _socksVersion) {
      _sendReply(_SocksReply.generalFailure);
      throw StateError('Unsupported SOCKS version');
    }

    if (command != 0x01) {
      _sendReply(_SocksReply.commandNotSupported);
      throw StateError('Unsupported SOCKS command');
    }

    int requiredLength;
    if (atyp == 0x01) {
      requiredLength = 10;
    } else if (atyp == 0x03) {
      if (_buffer.length < 5) return null;
      requiredLength = 7 + _buffer.peek(4);
    } else if (atyp == 0x04) {
      requiredLength = 22;
    } else {
      _sendReply(_SocksReply.addressTypeNotSupported);
      throw StateError('Unsupported SOCKS address type');
    }

    if (_buffer.length < requiredLength) return null;

    final request = _buffer.read(requiredLength);
    final host = _decodeHost(request, atyp);
    final portOffset = requiredLength - 2;
    final port = (request[portOffset] << 8) | request[portOffset + 1];

    return _TargetAddress(host, port);
  }

  String _decodeHost(Uint8List request, int atyp) {
    if (atyp == 0x01) {
      return '${request[4]}.${request[5]}.${request[6]}.${request[7]}';
    }

    if (atyp == 0x03) {
      final length = request[4];
      final bytes = request.sublist(5, 5 + length);
      return utf8.decode(bytes, allowMalformed: true);
    }

    final raw = request.sublist(4, 20);
    return InternetAddress.fromRawAddress(Uint8List.fromList(raw)).address;
  }

  void _sendMethodSelection(int method) {
    _client.add([_socksVersion, method]);
  }

  void _sendReply(_SocksReply reply) {
    _client.add([
      _socksVersion,
      reply.code,
      0x00,
      0x01,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
    ]);
  }
}

class _ByteBuffer {
  final _data = <int>[];
  int _offset = 0;

  int get length => _data.length - _offset;

  void add(List<int> chunk) {
    _data.addAll(chunk);
  }

  int peek(int index) => _data[_offset + index];

  Uint8List read(int count) {
    final slice = Uint8List.fromList(_data.sublist(_offset, _offset + count));
    _offset += count;

    if (_offset >= _data.length) {
      _data.clear();
      _offset = 0;
    } else if (_offset > 1024 && _offset * 2 > _data.length) {
      _data.removeRange(0, _offset);
      _offset = 0;
    }

    return slice;
  }

  Uint8List takeAll() {
    if (length == 0) return Uint8List(0);
    return read(length);
  }
}

class _TargetAddress {
  final String host;
  final int port;

  const _TargetAddress(this.host, this.port);
}

enum _SocksState {
  greeting,
  request,
  streaming,
}

enum _SocksReply {
  succeeded(0x00),
  generalFailure(0x01),
  connectionNotAllowed(0x02),
  connectionRefused(0x05),
  ttlExpired(0x06),
  hostUnreachable(0x04),
  commandNotSupported(0x07),
  addressTypeNotSupported(0x08);

  final int code;

  const _SocksReply(this.code);
}
