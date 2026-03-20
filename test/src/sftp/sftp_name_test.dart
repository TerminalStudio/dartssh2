import 'package:dartssh2/src/sftp/sftp_file_attrs.dart';
import 'package:dartssh2/src/sftp/sftp_name.dart';
import 'package:dartssh2/src/ssh_message.dart';
import 'package:test/test.dart';

void main() {
  test('SftpName writeTo/readFrom roundtrip', () {
    final original = SftpName(
      filename: 'report.txt',
      longname: '-rw-r--r-- 1 user group 10 report.txt',
      attr: SftpFileAttrs(
        size: 10,
        mode: const SftpFileMode.value((1 << 15) + 0x1A4),
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
}
