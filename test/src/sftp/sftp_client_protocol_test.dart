import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/src/message/msg_channel.dart';
import 'package:dartssh2/src/sftp/sftp_client.dart';
import 'package:dartssh2/src/sftp/sftp_errors.dart';
import 'package:dartssh2/src/sftp/sftp_file_attrs.dart';
import 'package:dartssh2/src/sftp/sftp_packet.dart';
import 'package:dartssh2/src/sftp/sftp_status_code.dart';
import 'package:dartssh2/src/ssh_channel.dart';
import 'package:dartssh2/src/ssh_message.dart';
import 'package:test/test.dart';

void main() {
  group('SftpClient protocol', () {
    test('handshake completes with version packet', () async {
      final harness = _SftpHarness();
      final initPayload = await harness.nextOutgoingPacket();
      final init = SftpInitPacket.decode(initPayload);
      expect(init.version, 3);

      harness.sendResponsePacket(
        SftpVersionPacket(3, {'fstatvfs@openssh.com': '2'}),
      );

      final handshake = await harness.client.handshake;
      expect(handshake.version, 3);
      expect(handshake.extensions['fstatvfs@openssh.com'], '2');

      harness.dispose();
    });

    test('stat uses lstat when followLink is false', () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();
      harness.sendResponsePacket(SftpVersionPacket(3));
      await harness.client.handshake;

      final statFuture = harness.client.stat('/tmp/file', followLink: false);
      final packet = await harness.nextOutgoingPacket();
      final lstat = SftpLStatPacket.decode(packet);

      harness.sendResponsePacket(
        SftpAttrsPacket(
          lstat.requestId,
          SftpFileAttrs(size: 55, mode: const SftpFileMode.value(1 << 15)),
        ),
      );

      final attrs = await statFuture;
      expect(attrs.size, 55);
      expect(attrs.isFile, isTrue);

      harness.dispose();
    });

    test('stat throws SftpStatusError on failure status', () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();
      harness.sendResponsePacket(SftpVersionPacket(3));
      await harness.client.handshake;

      final statFuture = harness.client.stat('/tmp/file');
      final packet = await harness.nextOutgoingPacket();
      final stat = SftpStatPacket.decode(packet);

      harness.sendResponsePacket(
        SftpStatusPacket(
          requestId: stat.requestId,
          code: SftpStatusCode.permissionDenied,
          message: 'denied',
        ),
      );

      await expectLater(
        statFuture,
        throwsA(
          isA<SftpStatusError>()
              .having((e) => e.code, 'code', SftpStatusCode.permissionDenied),
        ),
      );

      harness.dispose();
    });

    test('close aborts pending requests', () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();
      harness.sendResponsePacket(SftpVersionPacket(3));
      await harness.client.handshake;

      final openFuture = harness.client.open('/tmp/f');
      await harness.nextOutgoingPacket();

      harness.client.close();

      await expectLater(openFuture, throwsA(isA<SftpAbortError>()));
      harness.dispose();
    });

    test('download keeps chunk order with pipelined reads', () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();
      harness.sendResponsePacket(SftpVersionPacket(3));
      await harness.client.handshake;

      final sink = _CollectingSink();
      final downloadFuture = harness.client.download(
        '/tmp/file',
        sink,
        length: 8,
        chunkSize: 4,
        maxPendingRequests: 2,
      );

      final open = SftpOpenPacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpHandlePacket(open.requestId, Uint8List.fromList([1, 2, 3])),
      );

      final read1 = SftpReadPacket.decode(await harness.nextOutgoingPacket());
      final read2 = SftpReadPacket.decode(await harness.nextOutgoingPacket());

      expect(read1.offset, 0);
      expect(read2.offset, 4);

      harness.sendResponsePacket(
        SftpDataPacket(read2.requestId, Uint8List.fromList('EFGH'.codeUnits)),
      );
      harness.sendResponsePacket(
        SftpDataPacket(read1.requestId, Uint8List.fromList('ABCD'.codeUnits)),
      );

      final close = SftpClosePacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpStatusPacket(
          requestId: close.requestId,
          code: SftpStatusCode.ok,
          message: 'ok',
        ),
      );

      final bytes = await downloadFuture;
      expect(bytes, 8);
      expect(sink.bytes, Uint8List.fromList('ABCDEFGH'.codeUnits));

      harness.dispose();
    });

    test('read rejects invalid pipeline settings', () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();
      harness.sendResponsePacket(SftpVersionPacket(3));
      await harness.client.handshake;

      final fileFuture = harness.client.open('/tmp/file');
      final open = SftpOpenPacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpHandlePacket(open.requestId, Uint8List.fromList([1, 2, 3])),
      );
      final file = await fileFuture;

      await expectLater(
        file.read(chunkSize: 0).toList(),
        throwsA(isA<ArgumentError>()),
      );
      await expectLater(
        file.read(maxPendingRequests: 0).toList(),
        throwsA(isA<ArgumentError>()),
      );

      final closeFuture = file.close();
      final close = SftpClosePacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpStatusPacket(
          requestId: close.requestId,
          code: SftpStatusCode.ok,
          message: 'ok',
        ),
      );
      await closeFuture;
      harness.dispose();
    });

    test('downloadTo can close destination sink', () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();
      harness.sendResponsePacket(SftpVersionPacket(3));
      await harness.client.handshake;

      final fileFuture = harness.client.open('/tmp/file');
      final open = SftpOpenPacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpHandlePacket(open.requestId, Uint8List.fromList([1, 2, 3])),
      );
      final file = await fileFuture;

      final sink = _CollectingSink();
      final downloadFuture = file.downloadTo(
        sink,
        length: 4,
        chunkSize: 4,
        maxPendingRequests: 1,
        closeDestination: true,
      );

      final read = SftpReadPacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpDataPacket(read.requestId, Uint8List.fromList('ABCD'.codeUnits)),
      );

      final bytes = await downloadFuture;
      expect(bytes, 4);
      expect(sink.bytes, Uint8List.fromList('ABCD'.codeUnits));
      expect(sink.isClosed, isTrue);

      final closeFuture = file.close();
      final close = SftpClosePacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpStatusPacket(
          requestId: close.requestId,
          code: SftpStatusCode.ok,
          message: 'ok',
        ),
      );
      await closeFuture;
      harness.dispose();
    });

    test('download infers length from stat when not provided', () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();
      harness.sendResponsePacket(SftpVersionPacket(3));
      await harness.client.handshake;

      final sink = _CollectingSink();
      final downloadFuture = harness.client.download('/tmp/file', sink);

      final open = SftpOpenPacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpHandlePacket(open.requestId, Uint8List.fromList([1, 2, 3])),
      );

      final fstat = SftpFStatPacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpAttrsPacket(
          fstat.requestId,
          SftpFileAttrs(size: 4, mode: const SftpFileMode.value(1 << 15)),
        ),
      );

      final read = SftpReadPacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpDataPacket(read.requestId, Uint8List.fromList('WXYZ'.codeUnits)),
      );

      final close = SftpClosePacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpStatusPacket(
          requestId: close.requestId,
          code: SftpStatusCode.ok,
          message: 'ok',
        ),
      );

      final bytes = await downloadFuture;
      expect(bytes, 4);
      expect(sink.bytes, Uint8List.fromList('WXYZ'.codeUnits));
      harness.dispose();
    });
  });
}

class _CollectingSink implements StreamSink<List<int>> {
  final BytesBuilder _builder = BytesBuilder(copy: false);
  final Completer<void> _done = Completer<void>();
  var _isClosed = false;

  Uint8List get bytes => _builder.toBytes();

  bool get isClosed => _isClosed;

  @override
  void add(List<int> event) {
    _builder.add(event);
  }

  @override
  void addError(Object error, [StackTrace? stackTrace]) {}

  @override
  Future<void> addStream(Stream<List<int>> stream) async {
    await for (final chunk in stream) {
      add(chunk);
    }
  }

  @override
  Future<void> close() async {
    _isClosed = true;
    if (!_done.isCompleted) {
      _done.complete();
    }
  }

  @override
  Future<void> get done => _done.future;
}

class _SftpHarness {
  _SftpHarness() {
    _controller = SSHChannelController(
      localId: 1,
      localMaximumPacketSize: 1024 * 1024,
      localInitialWindowSize: 1024 * 1024,
      remoteId: 2,
      remoteMaximumPacketSize: 1024 * 1024,
      remoteInitialWindowSize: 1024 * 1024,
      sendMessage: _handleOutboundMessage,
    );
    client = SftpClient(_controller.channel);
  }

  late final SSHChannelController _controller;
  late final SftpClient client;

  final _outgoing = StreamController<Uint8List>.broadcast();
  var _disposed = false;

  void _handleOutboundMessage(SSHMessage message) {
    if (message is! SSH_Message_Channel_Data) return;
    final reader = SSHMessageReader(message.data);
    final length = reader.readUint32();
    final payload = reader.readBytes(length);
    _outgoing.add(payload);
  }

  Future<Uint8List> nextOutgoingPacket() => _outgoing.stream.first;

  void sendResponsePacket(SftpPacket packet) {
    final payload = packet.encode();
    final writer = SSHMessageWriter();
    writer.writeUint32(payload.length);
    writer.writeBytes(payload);

    _controller.handleMessage(
      SSH_Message_Channel_Data(
        recipientChannel: _controller.localId,
        data: writer.takeBytes(),
      ),
    );
  }

  void dispose() {
    if (_disposed) return;
    _disposed = true;

    try {
      client.close();
    } catch (_) {
      // SftpClient.close is not idempotent when already completed with error.
    }
    _controller.destroy();
    _outgoing.close();
  }
}
