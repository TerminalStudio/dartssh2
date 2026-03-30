import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dartssh2/src/dynamic_forward.dart';
import 'package:dartssh2/src/message/base.dart';
import 'package:dartssh2/src/ssh_channel.dart';
import 'package:dartssh2/src/ssh_forward.dart';
import 'package:test/test.dart';

void main() {
  group('startDynamicForward (io)', () {
    test('accepts SOCKS5 connect and proxies data', () async {
      late _DialedTunnel dialed;
      String? dialHost;
      int? dialPort;

      final forward = await startDynamicForward(
        bindHost: '127.0.0.1',
        bindPort: 0,
        options: const SSHDynamicForwardOptions(),
        dial: (host, port) async {
          dialHost = host;
          dialPort = port;
          dialed = _DialedTunnel.create();
          return dialed.channel;
        },
      );

      final client = await Socket.connect(forward.host, forward.port);
      final incoming = client.asBroadcastStream();
      addTearDown(() async {
        await client.close();
        await forward.close();
        dialed.dispose();
      });

      await _sendGreeting(client, incoming);
      final reply =
          await _sendConnectDomain(client, incoming, 'example.com', 443);

      expect(reply[0], 0x05);
      expect(reply[1], 0x00);
      expect(dialHost, 'example.com');
      expect(dialPort, 443);

      client.add(utf8.encode('hello'));
      await Future<void>.delayed(const Duration(milliseconds: 20));
      expect(utf8.decode(dialed.sentToRemote), 'hello');

      dialed.pushFromRemote(utf8.encode('world'));
      final tunneled = await _readAtLeast(incoming, 5);
      expect(utf8.decode(tunneled), 'world');
    });

    test('rejects connection when filter returns false', () async {
      var dialCalled = false;

      final forward = await startDynamicForward(
        bindHost: '127.0.0.1',
        bindPort: 0,
        options: const SSHDynamicForwardOptions(),
        filter: (_, __) => false,
        dial: (_, __) async {
          dialCalled = true;
          return _DialedTunnel.create().channel;
        },
      );
      addTearDown(() => forward.close());

      final client = await Socket.connect(forward.host, forward.port);
      final incoming = client.asBroadcastStream();
      addTearDown(() => client.close());

      await _sendGreeting(client, incoming);
      final reply =
          await _sendConnectDomain(client, incoming, 'blocked.test', 80);

      expect(reply[1], 0x02); // connection not allowed
      expect(dialCalled, isFalse);
    });

    test('rejects new connection when maxConnections is exceeded', () async {
      final tunnels = <_DialedTunnel>[];

      final forward = await startDynamicForward(
        bindHost: '127.0.0.1',
        bindPort: 0,
        options: const SSHDynamicForwardOptions(maxConnections: 1),
        dial: (_, __) async {
          final tunnel = _DialedTunnel.create();
          tunnels.add(tunnel);
          return tunnel.channel;
        },
      );
      addTearDown(() async {
        for (final tunnel in tunnels) {
          tunnel.dispose();
        }
        await forward.close();
      });

      final first = await Socket.connect(forward.host, forward.port);
      final firstIncoming = first.asBroadcastStream();
      addTearDown(() => first.close());
      await _sendGreeting(first, firstIncoming);
      final firstReply =
          await _sendConnectDomain(first, firstIncoming, 'one.test', 80);
      expect(firstReply[1], 0x00);

      final second = await Socket.connect(forward.host, forward.port);
      final secondIncoming = second.asBroadcastStream();
      addTearDown(() => second.close());
      await _sendGreeting(second, secondIncoming);
      final secondReply = await _sendConnectDomain(
        second,
        secondIncoming,
        'two.test',
        80,
      );
      expect(secondReply[1], 0x05); // connection refused
    });

    test('returns host unreachable when dial times out', () async {
      final neverCompletes = Completer<SSHForwardChannel>();

      final forward = await startDynamicForward(
        bindHost: '127.0.0.1',
        bindPort: 0,
        options: const SSHDynamicForwardOptions(
          connectTimeout: Duration(milliseconds: 30),
        ),
        dial: (_, __) => neverCompletes.future,
      );
      addTearDown(() => forward.close());

      final client = await Socket.connect(forward.host, forward.port);
      final incoming = client.asBroadcastStream();
      addTearDown(() => client.close());

      await _sendGreeting(client, incoming);
      final reply =
          await _sendConnectDomain(client, incoming, 'timeout.test', 80);

      expect(reply[1], 0x04); // host unreachable
    });

    test('expires idle handshake when no greeting is sent', () async {
      final forward = await startDynamicForward(
        bindHost: '127.0.0.1',
        bindPort: 0,
        options: const SSHDynamicForwardOptions(
          handshakeTimeout: Duration(milliseconds: 40),
        ),
        dial: (_, __) async => _DialedTunnel.create().channel,
      );
      addTearDown(() => forward.close());

      final client = await Socket.connect(forward.host, forward.port);
      final incoming = client.asBroadcastStream();
      addTearDown(() => client.close());

      final reply = await _readAtLeast(incoming, 10);
      expect(reply[0], 0x05);
      expect(reply[1], 0x06); // ttl expired
    });

    test('forwards pending bytes sent with CONNECT request', () async {
      late _DialedTunnel dialed;

      final forward = await startDynamicForward(
        bindHost: '127.0.0.1',
        bindPort: 0,
        options: const SSHDynamicForwardOptions(),
        dial: (_, __) async {
          dialed = _DialedTunnel.create();
          return dialed.channel;
        },
      );

      final client = await Socket.connect(forward.host, forward.port);
      final incoming = client.asBroadcastStream();
      addTearDown(() async {
        await client.close();
        await forward.close();
        dialed.dispose();
      });

      await _sendGreeting(client, incoming);

      final hostBytes = utf8.encode('pending.test');
      client.add([
        0x05,
        0x01,
        0x00,
        0x03,
        hostBytes.length,
        ...hostBytes,
        0x00,
        0x50,
        ...utf8.encode('EXTRA'),
      ]);

      final reply = await _readAtLeast(incoming, 10);
      expect(reply[1], 0x00);

      await Future<void>.delayed(const Duration(milliseconds: 20));
      expect(utf8.decode(dialed.sentToRemote), 'EXTRA');
    });

    test('rejects unsupported greeting version', () async {
      final forward = await startDynamicForward(
        bindHost: '127.0.0.1',
        bindPort: 0,
        options: const SSHDynamicForwardOptions(),
        dial: (_, __) async => _DialedTunnel.create().channel,
      );
      addTearDown(() => forward.close());

      final client = await Socket.connect(forward.host, forward.port);
      final incoming = client.asBroadcastStream();
      addTearDown(() => client.close());

      client.add([0x04, 0x01, 0x00]);
      final reply = await _readAtLeast(incoming, 2);
      expect(reply[0], 0x05);
      expect(reply[1], 0xFF);
    });

    test('rejects unsupported authentication method', () async {
      final forward = await startDynamicForward(
        bindHost: '127.0.0.1',
        bindPort: 0,
        options: const SSHDynamicForwardOptions(),
        dial: (_, __) async => _DialedTunnel.create().channel,
      );
      addTearDown(() => forward.close());

      final client = await Socket.connect(forward.host, forward.port);
      final incoming = client.asBroadcastStream();
      addTearDown(() => client.close());

      client.add([0x05, 0x01, 0x02]);
      final reply = await _readAtLeast(incoming, 2);
      expect(reply[0], 0x05);
      expect(reply[1], 0xFF);
    });

    test('rejects unsupported request version', () async {
      final forward = await startDynamicForward(
        bindHost: '127.0.0.1',
        bindPort: 0,
        options: const SSHDynamicForwardOptions(),
        dial: (_, __) async => _DialedTunnel.create().channel,
      );
      addTearDown(() => forward.close());

      final client = await Socket.connect(forward.host, forward.port);
      final incoming = client.asBroadcastStream();
      addTearDown(() => client.close());

      await _sendGreeting(client, incoming);
      client.add([0x04, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 22]);
      final reply = await _readAtLeast(incoming, 10);
      expect(reply[1], 0x01);
    });

    test('rejects unsupported request command', () async {
      final forward = await startDynamicForward(
        bindHost: '127.0.0.1',
        bindPort: 0,
        options: const SSHDynamicForwardOptions(),
        dial: (_, __) async => _DialedTunnel.create().channel,
      );
      addTearDown(() => forward.close());

      final client = await Socket.connect(forward.host, forward.port);
      final incoming = client.asBroadcastStream();
      addTearDown(() => client.close());

      await _sendGreeting(client, incoming);
      client.add([0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 22]);
      final reply = await _readAtLeast(incoming, 10);
      expect(reply[1], 0x07);
    });

    test('rejects unsupported address type', () async {
      final forward = await startDynamicForward(
        bindHost: '127.0.0.1',
        bindPort: 0,
        options: const SSHDynamicForwardOptions(),
        dial: (_, __) async => _DialedTunnel.create().channel,
      );
      addTearDown(() => forward.close());

      final client = await Socket.connect(forward.host, forward.port);
      final incoming = client.asBroadcastStream();
      addTearDown(() => client.close());

      await _sendGreeting(client, incoming);
      client.add([0x05, 0x01, 0x00, 0x7F, 0x00, 0x00]);
      final reply = await _readAtLeast(incoming, 10);
      expect(reply[1], 0x08);
    });

    test('supports IPv4 and IPv6 target addresses', () async {
      final tunnels = <_DialedTunnel>[];
      final dialedHosts = <String>[];

      final forward = await startDynamicForward(
        bindHost: '127.0.0.1',
        bindPort: 0,
        options: const SSHDynamicForwardOptions(),
        dial: (host, _) async {
          dialedHosts.add(host);
          final tunnel = _DialedTunnel.create();
          tunnels.add(tunnel);
          return tunnel.channel;
        },
      );
      addTearDown(() async {
        for (final tunnel in tunnels) {
          tunnel.dispose();
        }
        await forward.close();
      });

      final ipv4 = await Socket.connect(forward.host, forward.port);
      final ipv4Incoming = ipv4.asBroadcastStream();
      addTearDown(() => ipv4.close());
      await _sendGreeting(ipv4, ipv4Incoming);
      ipv4.add([0x05, 0x01, 0x00, 0x01, 192, 168, 1, 2, 0, 80]);
      final ipv4Reply = await _readAtLeast(ipv4Incoming, 10);
      expect(ipv4Reply[1], 0x00);

      final ipv6 = await Socket.connect(forward.host, forward.port);
      final ipv6Incoming = ipv6.asBroadcastStream();
      addTearDown(() => ipv6.close());
      await _sendGreeting(ipv6, ipv6Incoming);
      ipv6.add([
        0x05,
        0x01,
        0x00,
        0x04,
        0x20,
        0x01,
        0x0d,
        0xb8,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        1,
        0,
        22,
      ]);
      final ipv6Reply = await _readAtLeast(ipv6Incoming, 10);
      expect(ipv6Reply[1], 0x00);

      expect(dialedHosts.length, 2);
      expect(dialedHosts[0], '192.168.1.2');
      expect(dialedHosts[1], contains(':'));
    });
  });
}

Future<void> _sendGreeting(Socket socket, Stream<Uint8List> incoming) async {
  socket.add([0x05, 0x01, 0x00]);
  final greeting = await _readAtLeast(incoming, 2);
  expect(greeting[0], 0x05);
  expect(greeting[1], 0x00);
}

Future<Uint8List> _sendConnectDomain(
  Socket socket,
  Stream<Uint8List> incoming,
  String host,
  int port,
) async {
  final hostBytes = utf8.encode(host);
  socket.add([
    0x05,
    0x01,
    0x00,
    0x03,
    hostBytes.length,
    ...hostBytes,
    (port >> 8) & 0xff,
    port & 0xff,
  ]);
  return _readAtLeast(incoming, 10);
}

Future<Uint8List> _readAtLeast(
  Stream<Uint8List> incoming,
  int minBytes, {
  Duration timeout = const Duration(seconds: 1),
}) async {
  final completer = Completer<Uint8List>();
  final buffer = <int>[];
  late final StreamSubscription<Uint8List> sub;

  sub = incoming.listen(
    (chunk) {
      buffer.addAll(chunk);
      if (buffer.length >= minBytes && !completer.isCompleted) {
        completer.complete(Uint8List.fromList(buffer));
      }
    },
    onDone: () {
      if (!completer.isCompleted) {
        completer.complete(Uint8List.fromList(buffer));
      }
    },
    onError: (Object error, StackTrace stackTrace) {
      if (!completer.isCompleted) {
        completer.completeError(error, stackTrace);
      }
    },
    cancelOnError: true,
  );

  try {
    return await completer.future.timeout(timeout);
  } finally {
    await sub.cancel();
  }
}

class _DialedTunnel {
  _DialedTunnel._(this.channel, this._controller, this.sentToRemote);

  final SSHForwardChannel channel;
  final SSHChannelController _controller;
  final List<int> sentToRemote;

  factory _DialedTunnel.create() {
    final sentToRemote = <int>[];

    final controller = SSHChannelController(
      localId: 1,
      localMaximumPacketSize: 1024 * 1024,
      localInitialWindowSize: 1024 * 1024,
      remoteId: 2,
      remoteMaximumPacketSize: 1024 * 1024,
      remoteInitialWindowSize: 1024 * 1024,
      sendMessage: (message) {
        if (message is SSH_Message_Channel_Data) {
          sentToRemote.addAll(message.data);
        }
      },
    );

    return _DialedTunnel._(
      SSHForwardChannel(controller.channel),
      controller,
      sentToRemote,
    );
  }

  void pushFromRemote(List<int> data) {
    _controller.handleMessage(
      SSH_Message_Channel_Data(
        recipientChannel: _controller.localId,
        data: Uint8List.fromList(data),
      ),
    );
  }

  void dispose() {
    _controller.destroy();
  }
}
