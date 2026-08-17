import 'dart:async';
import 'dart:io';
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

      unawaited(harness.client.close());

      await expectLater(openFuture, throwsA(isA<SftpAbortError>()));
      harness.dispose();
    });

    test('close closes the underlying channel', () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();
      harness.sendResponsePacket(SftpVersionPacket(3));
      await harness.client.handshake;

      final closeFuture = harness.client.close();
      // The server acks the channel close, letting the teardown complete.
      harness.closeRemote();
      await closeFuture;

      await expectLater(harness.channelDone, completes);
      harness.dispose();
    });

    test('read ramps and replenishes its pipeline for out-of-order replies',
        () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();
      harness.sendResponsePacket(SftpVersionPacket(3));
      await harness.client.handshake;

      final sink = _CollectingSink();
      final downloadFuture = harness.client.download(
        '/tmp/file',
        sink,
        length: 16,
        chunkSize: 4,
        maxPendingRequests: 2,
      );

      final open = SftpOpenPacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpHandlePacket(open.requestId, Uint8List.fromList([1, 2, 3])),
      );

      final read1 = SftpReadPacket.decode(await harness.nextOutgoingPacket());
      expect(read1.offset, 0);

      final nextReads = harness.nextOutgoingPackets(2);
      harness.sendResponsePacket(
        SftpDataPacket(read1.requestId, Uint8List.fromList('ABCD'.codeUnits)),
      );

      final reads = (await nextReads).map(SftpReadPacket.decode).toList();
      final read2 = reads[0];
      final read3 = reads[1];
      expect(read2.offset, 4);
      expect(read3.offset, 8);

      final read4Future = harness.nextOutgoingPacket();
      harness.sendResponsePacket(
        SftpDataPacket(read3.requestId, Uint8List.fromList('IJKL'.codeUnits)),
      );
      final read4 = SftpReadPacket.decode(await read4Future);
      expect(read4.offset, 12);

      harness.sendResponsePacket(
        SftpDataPacket(read4.requestId, Uint8List.fromList('MNOP'.codeUnits)),
      );
      harness.sendResponsePacket(
        SftpDataPacket(read2.requestId, Uint8List.fromList('EFGH'.codeUnits)),
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
      expect(bytes, 16);
      expect(sink.bytes, Uint8List.fromList('ABCDEFGHIJKLMNOP'.codeUnits));

      harness.dispose();
    });

    test('a one-off tiny reply does not shrink later reads', () async {
      final lengths = await _recordReadLengths(
        totalLength: 8192 * 3,
        chunkSize: 8192,
        firstReplyLength: 1,
      );

      // The suffix is retried, and the reads after it stay at full size
      // instead of being pinned to the 512 byte floor.
      expect(lengths, [8192, 8191, 8192, 8192]);
    });

    test('a large short reply clamps later reads, as OpenSSH does', () async {
      final lengths = await _recordReadLengths(
        totalLength: 8192 * 3,
        chunkSize: 8192,
        firstReplyLength: 4096,
      );

      // A reply this size reads as the server's real capacity, so the client
      // settles there and stops asking for more than the server will give.
      expect(lengths, [8192, 4096, 4096, 4096, 4096, 4096]);
    });

    test('read retries the missing suffix after a short data packet', () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();
      harness.sendResponsePacket(SftpVersionPacket(3));
      await harness.client.handshake;

      final sink = _CollectingSink();
      final downloadFuture = harness.client.download(
        '/tmp/file',
        sink,
        length: 1536,
        chunkSize: 1024,
        maxPendingRequests: 2,
      );

      final open = SftpOpenPacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpHandlePacket(open.requestId, Uint8List.fromList([1, 2, 3])),
      );

      final read1 = SftpReadPacket.decode(await harness.nextOutgoingPacket());
      expect(read1.offset, 0);
      expect(read1.length, 1024);

      final nextReads = harness.nextOutgoingPackets(2);
      harness.sendResponsePacket(
        SftpDataPacket(read1.requestId, Uint8List.fromList([1])),
      );

      final reads = (await nextReads).map(SftpReadPacket.decode).toList();
      final retry = reads[0];
      final read2 = reads[1];
      expect(retry.offset, 1);
      expect(retry.length, 1023);
      expect(read2.offset, 1024);
      expect(read2.length, 512);

      harness.sendResponsePacket(
        SftpDataPacket(
          read2.requestId,
          Uint8List.fromList(List<int>.filled(512, 3)),
        ),
      );
      harness.sendResponsePacket(
        SftpDataPacket(
          retry.requestId,
          Uint8List.fromList(List<int>.filled(1023, 2)),
        ),
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
      expect(bytes, 1536);
      expect(
        sink.bytes,
        Uint8List.fromList([
          1,
          ...List<int>.filled(1023, 2),
          ...List<int>.filled(512, 3),
        ]),
      );

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

    test('downloadTo reports progress callback', () async {
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

      var progress = -1;
      final sink = _CollectingSink();
      final downloadFuture = file.downloadTo(
        sink,
        length: 4,
        chunkSize: 4,
        maxPendingRequests: 1,
        onProgress: (value) => progress = value,
      );

      final read = SftpReadPacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpDataPacket(read.requestId, Uint8List.fromList('ABCD'.codeUnits)),
      );

      final bytes = await downloadFuture;
      expect(bytes, 4);
      expect(progress, 4);

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

    test('write() returns writer and writes streamed data', () async {
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

      final writer = file.write(
        Stream.value(Uint8List.fromList('ABCD'.codeUnits)),
      );

      final write = SftpWritePacket.decode(await harness.nextOutgoingPacket());
      expect(write.offset, 0);
      expect(write.data, Uint8List.fromList('ABCD'.codeUnits));

      harness.sendResponsePacket(
        SftpStatusPacket(
          requestId: write.requestId,
          code: SftpStatusCode.ok,
          message: 'ok',
        ),
      );

      await writer.done;
      expect(writer.progress, 4);

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

    test('rename uses posix-rename extension when advertised', () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();
      harness.sendResponsePacket(
        SftpVersionPacket(3, {'posix-rename@openssh.com': '1'}),
      );
      await harness.client.handshake;

      final renameFuture = harness.client.rename('/tmp/a', '/tmp/b');
      final packet = await harness.nextOutgoingPacket();
      final extended = SftpExtendedPacket.decode(packet);

      harness.sendResponsePacket(
        SftpStatusPacket(
          requestId: extended.requestId,
          code: SftpStatusCode.ok,
          message: 'ok',
        ),
      );

      await renameFuture;
      harness.dispose();
    });

    test('rename falls back to SSH_FXP_RENAME without extension', () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();
      harness.sendResponsePacket(SftpVersionPacket(3));
      await harness.client.handshake;

      final renameFuture = harness.client.rename('/tmp/a', '/tmp/b');
      final packet = await harness.nextOutgoingPacket();
      final rename = SftpRenamePacket.decode(packet);
      expect(rename.oldPath, '/tmp/a');
      expect(rename.newPath, '/tmp/b');

      harness.sendResponsePacket(
        SftpStatusPacket(
          requestId: rename.requestId,
          code: SftpStatusCode.ok,
          message: 'ok',
        ),
      );

      await renameFuture;
      harness.dispose();
    });

    test('downloadToRandomAccess writes out-of-order chunks at offset',
        () async {
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

      final tempDir = await Directory.systemTemp.createTemp('sftp_ra_test');
      final tempFile = File('${tempDir.path}/ra.bin');
      final raf = await tempFile.open(mode: FileMode.write);

      final downloadFuture = file.downloadToRandomAccess(
        raf,
        length: 12,
        chunkSize: 4,
        maxPendingRequests: 2,
      );

      // activeReadLimit starts at 1, so only read1 is issued initially.
      final read1 = SftpReadPacket.decode(await harness.nextOutgoingPacket());
      expect(read1.offset, 0);
      // Replying to read1 bumps activeReadLimit to 2, which schedules read2
      // and read3 together (both fit within the limit now).
      harness.sendResponsePacket(
        SftpDataPacket(read1.requestId, Uint8List.fromList('ABCD'.codeUnits)),
      );
      final read2 = SftpReadPacket.decode(await harness.nextOutgoingPacket());
      final read3 = SftpReadPacket.decode(await harness.nextOutgoingPacket());
      expect(read2.offset, 4);
      expect(read3.offset, 8);

      // Reply out of order: read3 before read2. downloadToRandomAccess must
      // write each chunk at its own offset regardless of arrival order.
      harness.sendResponsePacket(
        SftpDataPacket(read3.requestId, Uint8List.fromList('IJKL'.codeUnits)),
      );
      harness.sendResponsePacket(
        SftpDataPacket(read2.requestId, Uint8List.fromList('EFGH'.codeUnits)),
      );

      final bytes = await downloadFuture;
      expect(bytes, 12);

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

      await raf.close();

      final contents = await tempFile.readAsBytes();
      expect(contents, Uint8List.fromList('ABCDEFGHIJKL'.codeUnits));

      await tempDir.delete(recursive: true);
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

/// Downloads [totalLength] bytes, answering the first read with only
/// [firstReplyLength] bytes and filling every read after it, and returns the
/// length the client asked for on each read request.
Future<List<int>> _recordReadLengths({
  required int totalLength,
  required int chunkSize,
  required int firstReplyLength,
}) async {
  final harness = _SftpHarness();
  await harness.nextOutgoingPacket();
  harness.sendResponsePacket(SftpVersionPacket(3));
  await harness.client.handshake;

  final sink = _CollectingSink();
  final downloadFuture = harness.client.download(
    '/tmp/file',
    sink,
    length: totalLength,
    chunkSize: chunkSize,
    maxPendingRequests: 1,
  );

  final open = SftpOpenPacket.decode(await harness.nextOutgoingPacket());
  harness.sendResponsePacket(
    SftpHandlePacket(open.requestId, Uint8List.fromList([1, 2, 3])),
  );

  final requestedLengths = <int>[];
  var delivered = 0;

  while (delivered < totalLength) {
    final packet = await harness.nextOutgoingPacket();
    if (packet[0] != SftpReadPacket.packetType) break;

    final read = SftpReadPacket.decode(packet);
    requestedLengths.add(read.length);

    final replyLength = requestedLengths.length == 1
        ? firstReplyLength
        : read.length;
    delivered += replyLength;

    harness.sendResponsePacket(
      SftpDataPacket(
        read.requestId,
        Uint8List.fromList(List<int>.filled(replyLength, 7)),
      ),
    );
  }

  final close = SftpClosePacket.decode(await harness.nextOutgoingPacket());
  harness.sendResponsePacket(
    SftpStatusPacket(
      requestId: close.requestId,
      code: SftpStatusCode.ok,
      message: 'ok',
    ),
  );

  expect(await downloadFuture, totalLength);
  expect(sink.bytes, hasLength(totalLength));

  harness.dispose();
  return requestedLengths;
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

  Future<List<Uint8List>> nextOutgoingPackets(int count) =>
      _outgoing.stream.take(count).toList();

  Future<void> get channelDone => _controller.channel.done;

  void closeRemote() {
    _controller.handleMessage(
      SSH_Message_Channel_Close(recipientChannel: _controller.localId),
    );
  }

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

    unawaited(client.close());
    _controller.destroy();
    _outgoing.close();
  }
}
