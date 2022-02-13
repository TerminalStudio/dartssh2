import 'dart:io';

import 'package:dartssh2/src/sftp/sftp_file_attrs.dart';
import 'package:dartssh2/src/ssh_message.dart';

enum SftpFileType { File, Directory, BlockSpecial, CharacterSpecial, Fifo, SymbolicLink, Socket }

class SftpName {
  final String filename;

  final String longname;

  final SftpFileAttrs attr;

  SftpName({
    required this.filename,
    required this.longname,
    required this.attr,
  });

  SftpFileType get fileType {
    if (longname.isNotEmpty) {
      switch (longname.substring(0, 1)) {
        case '-':
          return SftpFileType.File;
        case 'd':
          return SftpFileType.Directory;
        case 'b':
          return SftpFileType.BlockSpecial;
        case 'c':
          return SftpFileType.CharacterSpecial;
        case 'p':
          return SftpFileType.Fifo;
        case 'l':
          return SftpFileType.SymbolicLink;
        case 's':
          return SftpFileType.Socket;
      }
    }
    throw FileSystemException("Unable to determine file type", filename);
  }

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
