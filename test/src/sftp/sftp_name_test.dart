import 'dart:typed_data';

import 'package:dartssh2/src/sftp/sftp_file_attrs.dart';
import 'package:dartssh2/src/sftp/sftp_name.dart';
import 'package:dartssh2/src/message/base.dart';
import 'package:test/test.dart';

void main() {
  test('SftpName writeTo/readFrom roundtrip', () {
    final original = SftpName(
      filename: 'report.txt',
      longname: '-rw-r--r-- 1 user group 10 report.txt',
      attr: SftpFileAttrs(
        size: 10,
        mode: const SftpFileMode.value(
            (1 << 15) + 0x1A4), // 0x1A4 = 0644 rw-r--r--
      ),
    );

    final writer = SSHMessageWriter();
    original.writeTo(writer);

    final reader = SSHMessageReader(writer.takeBytes());
    final decoded = SftpName.readFrom(reader);

    expect(decoded.filename, 'report.txt');
    expect(decoded.longname, '-rw-r--r-- 1 user group 10 report.txt');
    expect(decoded.attr.size, 10);
    expect(decoded.attr.isFile, isTrue);
  });

  test('SftpName.readFrom tolerates malformed UTF-8 bytes', () {
    final writer = SSHMessageWriter();
    writer.writeString(Uint8List.fromList([0x66, 0x6f, 0x80, 0x6f]));
    writer.writeString(Uint8List.fromList([0x6c, 0x73, 0xff]));
    SftpFileAttrs().writeTo(writer);

    final reader = SSHMessageReader(writer.takeBytes());
    final decoded = SftpName.readFrom(reader);

    expect(decoded.filename, 'fo\uFFFDo');
    expect(decoded.longname, 'ls\uFFFD');
    expect(decoded.attr.size, isNull);
  });
}
