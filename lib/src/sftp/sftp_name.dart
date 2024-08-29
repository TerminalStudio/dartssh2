import 'package:dartssh2/src/sftp/sftp_file_attrs.dart';
import 'package:dartssh2/src/ssh_message.dart';

class SftpName {
  final String filename;

  final String longname;

  final SftpFileAttrs attr;

  SftpName({
    required this.filename,
    required this.longname,
    required this.attr,
  });

  factory SftpName.readFrom(SSHMessageReader reader) {
    final filename = reader.readUtf8();
    final longname = reader.readUtf8();
    final attr = SftpFileAttrs.readFrom(reader);
    return SftpName(
      filename: filename,
      longname: longname,
      attr: attr,
    );
  }

  void writeTo(SSHMessageWriter writer) {
    writer.writeUtf8(filename);
    writer.writeUtf8(longname);
    attr.writeTo(writer);
  }

  @override
  String toString() {
    return 'SftpName(filename: $filename, longname: $longname, attr: $attr)';
  }
}
