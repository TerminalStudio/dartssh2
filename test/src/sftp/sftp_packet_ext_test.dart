import 'dart:typed_data';

import 'package:dartssh2/src/sftp/sftp_packet_ext.dart';
import 'package:dartssh2/src/ssh_message.dart';
import 'package:test/test.dart';

void main() {
  group('SFTP extended payload', () {
    test('statvfs request encodes name + path', () {
      final request = SftpStatVfsRequest(path: '/tmp');
      final encoded = request.encode();
      final reader = SSHMessageReader(encoded);

      expect(reader.readUtf8(), 'statvfs@openssh.com');
      expect(reader.readUtf8(), '/tmp');
      expect(reader.isDone, isTrue);
    });

    test('fstatvfs request encodes name + handle', () {
      final request =
          SftpFstatVfsRequest(handle: Uint8List.fromList([1, 2, 3]));
      final encoded = request.encode();
      final reader = SSHMessageReader(encoded);

      expect(reader.readUtf8(), 'fstatvfs@openssh.com');
      expect(reader.readString(), Uint8List.fromList([1, 2, 3]));
      expect(reader.isDone, isTrue);
    });

    test('statvfs reply decodes all fields in order', () {
      final writer = SSHMessageWriter();
      for (var i = 1; i <= 11; i++) {
        writer.writeUint64(i);
      }

      final reply = SftpStatVfsReply.decode(writer.takeBytes());

      expect(reply.blockSize, 1);
      expect(reply.fundamentalBlockSize, 2);
      expect(reply.totalBlocks, 3);
      expect(reply.freeBlocks, 4);
      expect(reply.freeBlocksForNonRoot, 5);
      expect(reply.totalInodes, 6);
      expect(reply.freeInodes, 7);
      expect(reply.freeInodesForNonRoot, 8);
      expect(reply.fileSystemId, 9);
      expect(reply.flag, 10);
      expect(reply.maximumFilenameLength, 11);
    });
  });
}
