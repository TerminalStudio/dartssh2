import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/src/sftp/sftp_client.dart';
import 'package:dartssh2/src/sftp/sftp_errors.dart';
import 'package:dartssh2/src/sftp/sftp_file_attrs.dart';
import 'package:dartssh2/src/sftp/sftp_packet.dart';
import 'package:dartssh2/src/sftp/sftp_status_code.dart';
import 'package:dartssh2/src/ssh_channel.dart';
import 'package:dartssh2/src/message/base.dart';
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
  });
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
