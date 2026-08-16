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
  group('SftpFile unit tests', () {
    test('toString formats handle correctly', () {
      final harness = _SftpTestHarness();
      final file = SftpFile(harness.client, Uint8List.fromList([0xAB, 0xCD]));
      expect(file.toString(), 'SftpFile(0xabcd)');
      expect(file.isClosed, isFalse);
      harness.dispose();
    });

    test('SftpHandsake toString formats version and extensions', () {
      final handshake = SftpHandsake(3, {'test@example.com': '1'});
      expect(handshake.toString(), contains('3'));
      expect(handshake.toString(), contains('test@example.com'));
      expect(handshake.version, 3);
      expect(handshake.extensions['test@example.com'], '1');
    });

    test('close closes remote handle and updates isClosed', () async {
      final harness = _SftpTestHarness();
      await harness.completeHandshake();

      final file = SftpFile(harness.client, Uint8List.fromList([1, 2, 3]));
      final closeFuture = file.close();

      final packet = await harness.nextOutgoingPacket();
      final closePacket = SftpClosePacket.decode(packet);
      expect(closePacket.handle, Uint8List.fromList([1, 2, 3]));

      harness.sendResponsePacket(
        SftpStatusPacket(
          requestId: closePacket.requestId,
          code: SftpStatusCode.ok,
          message: '',
        ),
      );

      await closeFuture;
      expect(file.isClosed, isTrue);

      // Calling close again is a no-op.
      await file.close();

      // Operations on closed file throw SftpError.
      await expectLater(file.stat(), throwsA(isA<SftpError>()));
      await expectLater(file.setStat(SftpFileAttrs()), throwsA(isA<SftpError>()));
      await expectLater(file.read().toList(), throwsA(isA<SftpError>()));
      await expectLater(file.writeBytes(Uint8List(0)), throwsA(isA<SftpError>()));

      harness.dispose();
    });

    test('stat and setStat work', () async {
      final harness = _SftpTestHarness();
      await harness.completeHandshake();

      final file = SftpFile(harness.client, Uint8List.fromList([1]));

      // stat
      final statFuture = file.stat();
      final packet1 = await harness.nextOutgoingPacket();
      final fstat = SftpFStatPacket.decode(packet1);
      harness.sendResponsePacket(
        SftpAttrsPacket(fstat.requestId, SftpFileAttrs(size: 1024)),
      );
      final attrs = await statFuture;
      expect(attrs.size, 1024);

      // setStat
      final setStatFuture = file.setStat(SftpFileAttrs(size: 512));
      final packet2 = await harness.nextOutgoingPacket();
      final fsetstat = SftpFSetStatPacket.decode(packet2);
      harness.sendResponsePacket(
        SftpStatusPacket(
          requestId: fsetstat.requestId,
          code: SftpStatusCode.ok,
          message: '',
        ),
      );
      await setStatFuture;

      harness.dispose();
    });

    test('read with invalid parameters throws', () async {
      final harness = _SftpTestHarness();
      await harness.completeHandshake();
      final file = SftpFile(harness.client, Uint8List.fromList([1]));

      expect(
        () => file.read(chunkSize: 0).toList(),
        throwsA(isA<ArgumentError>()),
      );
      expect(
        () => file.read(maxPendingRequests: -1).toList(),
        throwsA(isA<ArgumentError>()),
      );

      harness.dispose();
    });

    test('read with zero length returns empty stream', () async {
      final harness = _SftpTestHarness();
      await harness.completeHandshake();
      final file = SftpFile(harness.client, Uint8List.fromList([1]));

      final chunks = await file.read(length: 0).toList();
      expect(chunks, isEmpty);

      harness.dispose();
    });

    test('read streams chunks and triggers progress', () async {
      final harness = _SftpTestHarness();
      await harness.completeHandshake();
      final file = SftpFile(harness.client, Uint8List.fromList([1]));

      final progressList = <int>[];
      final readFuture = file
          .read(
            length: 10,
            onProgress: (p) => progressList.add(p),
          )
          .toList();

      final packet = await harness.nextOutgoingPacket();
      final readPacket = SftpReadPacket.decode(packet);
      expect(readPacket.length, 10);

      harness.sendResponsePacket(
        SftpDataPacket(readPacket.requestId, Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])),
      );

      final chunks = await readFuture;
      expect(chunks.length, 1);
      expect(chunks.first.length, 10);
      expect(progressList, [10]);

      harness.dispose();
    });

    test('readBytes reads full content', () async {
      final harness = _SftpTestHarness();
      await harness.completeHandshake();
      final file = SftpFile(harness.client, Uint8List.fromList([1]));

      final readFuture = file.readBytes(length: 4);

      final packet = await harness.nextOutgoingPacket();
      final readPacket = SftpReadPacket.decode(packet);

      harness.sendResponsePacket(
        SftpDataPacket(readPacket.requestId, Uint8List.fromList([10, 20, 30, 40])),
      );

      final bytes = await readFuture;
      expect(bytes, Uint8List.fromList([10, 20, 30, 40]));

      harness.dispose();
    });

    test('writeBytes writes chunks', () async {
      final harness = _SftpTestHarness();
      await harness.completeHandshake();
      final file = SftpFile(harness.client, Uint8List.fromList([1]));

      final writeFuture = file.writeBytes(Uint8List.fromList([1, 2, 3]));

      final packet = await harness.nextOutgoingPacket();
      final writePacket = SftpWritePacket.decode(packet);
      expect(writePacket.data, Uint8List.fromList([1, 2, 3]));

      harness.sendResponsePacket(
        SftpStatusPacket(
          requestId: writePacket.requestId,
          code: SftpStatusCode.ok,
          message: '',
        ),
      );

      await writeFuture;
      harness.dispose();
    });

    test('statvfs fetches filesystem stats', () async {
      final harness = _SftpTestHarness();
      await harness.completeHandshake(extensions: {'fstatvfs@openssh.com': '2'});
      final file = SftpFile(harness.client, Uint8List.fromList([1]));

      final statvfsFuture = file.statvfs();

      final packet = await harness.nextOutgoingPacket();
      final extPacket = SftpExtendedPacket.decode(packet);
      final extReader = SSHMessageReader(extPacket.payload);
      final extName = extReader.readUtf8();
      expect(extName, 'fstatvfs@openssh.com');

      final writer = SSHMessageWriter();
      writer.writeUint64(4096); // blockSize
      writer.writeUint64(4096); // fundamentalBlockSize
      writer.writeUint64(1000); // totalBlocks
      writer.writeUint64(500); // freeBlocks
      writer.writeUint64(450); // freeBlocksForNonRoot
      writer.writeUint64(10000); // totalInodes
      writer.writeUint64(5000); // freeInodes
      writer.writeUint64(4500); // freeInodesForNonRoot
      writer.writeUint64(1); // fileSystemId
      writer.writeUint64(0); // flag
      writer.writeUint64(255); // maximumFilenameLength

      harness.sendResponsePacket(
        SftpExtendedReplyPacket(extPacket.requestId, writer.takeBytes()),
      );

      final statvfs = await statvfsFuture;
      expect(statvfs.blockSize, 4096);
      expect(statvfs.totalBlocks, 1000);
      expect(statvfs.freeBlocks, 500);
      expect(statvfs.toString(), contains('blockSize: 4096'));

      harness.dispose();
    });

    test('downloadTo downloads stream and respects closeDestination', () async {
      final harness = _SftpTestHarness();
      await harness.completeHandshake();
      final file = SftpFile(harness.client, Uint8List.fromList([1]));

      final sink = _MockStreamSink();
      final downloadFuture = file.downloadTo(
        sink,
        length: 5,
        closeDestination: true,
      );

      final packet = await harness.nextOutgoingPacket();
      final readPacket = SftpReadPacket.decode(packet);
      expect(readPacket.length, 5);

      harness.sendResponsePacket(
        SftpDataPacket(readPacket.requestId, Uint8List.fromList([1, 2, 3, 4, 5])),
      );

      final downloadedBytes = await downloadFuture;
      expect(downloadedBytes, 5);
      expect(sink.isClosed, isTrue);

      harness.dispose();
    });
  });
}

class _MockStreamSink implements StreamSink<List<int>> {
  final buffer = BytesBuilder();
  var isClosed = false;
  final completer = Completer<void>();

  @override
  void add(List<int> event) {
    buffer.add(event);
  }

  @override
  void addError(Object error, [StackTrace? stackTrace]) {}

  @override
  Future<void> addStream(Stream<List<int>> stream) async {
    await for (final chunk in stream) {
      buffer.add(chunk);
    }
  }

  @override
  Future<void> close() async {
    isClosed = true;
    if (!completer.isCompleted) completer.complete();
  }

  @override
  Future<void> get done => completer.future;
}

class _SftpTestHarness {
  _SftpTestHarness() {
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

  Future<void> completeHandshake({Map<String, String>? extensions}) async {
    final init = await nextOutgoingPacket();
    expect(SftpInitPacket.decode(init).version, 3);
    sendResponsePacket(SftpVersionPacket(3, extensions ?? {}));
    await client.handshake;
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
