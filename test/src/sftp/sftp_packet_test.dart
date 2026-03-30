import 'dart:typed_data';

import 'package:dartssh2/src/sftp/sftp_file_attrs.dart';
import 'package:dartssh2/src/sftp/sftp_name.dart';
import 'package:dartssh2/src/sftp/sftp_packet.dart';
import 'package:test/test.dart';

void main() {
  group('SFTP packet roundtrips', () {
    final attrs = SftpFileAttrs(
      size: 123,
      userID: 1000,
      groupID: 1000,
      mode: const SftpFileMode.value(0x8000 | 0x1A4),
      accessTime: 11,
      modifyTime: 22,
      extended: {'k': 'v'},
    );

    test('init/version packets keep extensions', () {
      final init = SftpInitPacket(3, {'posix-rename@openssh.com': '1'});
      final decodedInit = SftpInitPacket.decode(init.encode());
      expect(decodedInit.version, 3);
      expect(decodedInit.extensions['posix-rename@openssh.com'], '1');

      final version = SftpVersionPacket(3, {'fstatvfs@openssh.com': '2'});
      final decodedVersion = SftpVersionPacket.decode(version.encode());
      expect(decodedVersion.version, 3);
      expect(decodedVersion.extensions['fstatvfs@openssh.com'], '2');
    });

    test('request packets decode expected fields', () {
      final open = SftpOpenPacket(1, '/tmp/a', 0x12, attrs);
      final openDecoded = SftpOpenPacket.decode(open.encode());
      expect(openDecoded.requestId, 1);
      expect(openDecoded.path, '/tmp/a');
      expect(openDecoded.flags, 0x12);
      expect(openDecoded.attrs.size, 123);

      final read = SftpReadPacket(
        requestId: 2,
        handle: Uint8List.fromList([1, 2]),
        offset: 42,
        length: 9,
      );
      final readDecoded = SftpReadPacket.decode(read.encode());
      expect(readDecoded.requestId, 2);
      expect(readDecoded.handle, Uint8List.fromList([1, 2]));
      expect(readDecoded.offset, 42);
      expect(readDecoded.length, 9);

      final write = SftpWritePacket(
        requestId: 3,
        handle: Uint8List.fromList([3]),
        offset: 7,
        data: Uint8List.fromList([8, 9]),
      );
      final writeDecoded = SftpWritePacket.decode(write.encode());
      expect(writeDecoded.requestId, 3);
      expect(writeDecoded.handle, Uint8List.fromList([3]));
      expect(writeDecoded.offset, 7);
      expect(writeDecoded.data, Uint8List.fromList([8, 9]));

      final rename = SftpRenamePacket(4, '/a', '/b');
      final renameDecoded = SftpRenamePacket.decode(rename.encode());
      expect(renameDecoded.requestId, 4);
      expect(renameDecoded.oldPath, '/a');
      expect(renameDecoded.newPath, '/b');
    });

    test('response packets decode expected fields', () {
      final status = SftpStatusPacket(
        requestId: 7,
        code: 5,
        message: 'err',
        language: 'en',
      );
      final statusDecoded = SftpStatusPacket.decode(status.encode());
      expect(statusDecoded.requestId, 7);
      expect(statusDecoded.code, 5);
      expect(statusDecoded.message, 'err');
      expect(statusDecoded.language, 'en');

      final data = SftpDataPacket(8, Uint8List.fromList([1, 2, 3]));
      final dataDecoded = SftpDataPacket.decode(data.encode());
      expect(dataDecoded.requestId, 8);
      expect(dataDecoded.data, Uint8List.fromList([1, 2, 3]));

      final name = SftpName(
        filename: 'f.txt',
        longname: '-rw-r--r-- f.txt',
        attr: attrs,
      );
      final names = SftpNamePacket(9, [name]);
      final namesDecoded = SftpNamePacket.decode(names.encode());
      expect(namesDecoded.requestId, 9);
      expect(namesDecoded.names.length, 1);
      expect(namesDecoded.names.single.filename, 'f.txt');
      expect(namesDecoded.names.single.longname, '-rw-r--r-- f.txt');
      expect(namesDecoded.names.single.attr.size, 123);

      final attrsPacket = SftpAttrsPacket(10, attrs);
      final attrsDecoded = SftpAttrsPacket.decode(attrsPacket.encode());
      expect(attrsDecoded.requestId, 10);
      expect(attrsDecoded.attrs.size, 123);
      expect(attrsDecoded.attrs.extended?['k'], 'v');
    });

    test('extended packets preserve raw payload', () {
      final payload = Uint8List.fromList([10, 20, 30, 40]);
      final request = SftpExtendedPacket(11, payload);
      final requestDecoded = SftpExtendedPacket.decode(request.encode());
      expect(requestDecoded.requestId, 11);
      expect(requestDecoded.payload, payload);

      final reply = SftpExtendedReplyPacket(12, payload);
      final replyDecoded = SftpExtendedReplyPacket.decode(reply.encode());
      expect(replyDecoded.requestId, 12);
      expect(replyDecoded.payload, payload);
    });
  });
}
