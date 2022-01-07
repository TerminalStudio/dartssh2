import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dartssh2/src/sftp/sftp_file_attrs.dart';
import 'package:dartssh2/src/sftp/sftp_name.dart';
import 'package:dartssh2/src/ssh_message.dart';

//  SSH_FXP_INIT                1   init
//  SSH_FXP_VERSION             2   init-reply
//  SSH_FXP_OPEN                3   ---> SSH_FXP_STATUS | SSH_FXP_HANDLE
//  SSH_FXP_CLOSE               4   ---> SSH_FXP_STATUS
//  SSH_FXP_READ                5   ---> SSH_FXP_STATUS | SSH_FXP_DATA
//  SSH_FXP_WRITE               6   ---> SSH_FXP_STATUS
//  SSH_FXP_LSTAT               7   ---> SSH_FXP_STATUS | SSH_FXP_ATTRS
//  SSH_FXP_FSTAT               8   ---> SSH_FXP_STATUS | SSH_FXP_ATTRS
//  SSH_FXP_SETSTAT             9   ---> SSH_FXP_STATUS
//  SSH_FXP_FSETSTAT           10   ---> SSH_FXP_STATUS
//  SSH_FXP_OPENDIR            11   ---> SSH_FXP_STATUS | SSH_FXP_HANDLE
//  SSH_FXP_READDIR            12   ---> SSH_FXP_STATUS | SSH_FXP_NAME
//  SSH_FXP_REMOVE             13   ---> SSH_FXP_STATUS
//  SSH_FXP_MKDIR              14   ---> SSH_FXP_STATUS
//  SSH_FXP_RMDIR              15   ---> SSH_FXP_STATUS
//  SSH_FXP_REALPATH           16   ---> SSH_FXP_STATUS | SSH_FXP_NAME
//  SSH_FXP_STAT               17   ---> SSH_FXP_STATUS | SSH_FXP_ATTRS
//  SSH_FXP_RENAME             18   ---> SSH_FXP_STATUS
//  SSH_FXP_READLINK           19   ---> SSH_FXP_STATUS | SSH_FXP_NAME
//  SSH_FXP_SYMLINK            20   ---> SSH_FXP_STATUS

// SSH_FXP_STATUS            101
// SSH_FXP_HANDLE            102   <--- SSH_FXP_OPEN | SSH_FXP_OPENDIR
// SSH_FXP_DATA              103
// SSH_FXP_NAME              104
// SSH_FXP_ATTRS             105
// SSH_FXP_EXTENDED          200
// SSH_FXP_EXTENDED_REPLY    201

abstract class SftpPacket {
  Uint8List encode();
}

abstract class SftpRequestPacket implements SftpPacket {
  int get requestId;
}

abstract class SftpResponsePacket implements SftpPacket {
  int get requestId;
}

class SftpInitPacket implements SftpPacket {
  static const int packetType = 1;

  final int version;

  final Map<String, String> extensions;

  SftpInitPacket(this.version, [this.extensions = const {}]);

  factory SftpInitPacket.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    reader.readUint8(); // packet type
    final version = reader.readUint32();
    final extensions = <String, String>{};
    while (reader.isDone) {
      final name = reader.readUtf8();
      final value = reader.readUtf8();
      extensions[name] = value;
    }
    return SftpInitPacket(version, extensions);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(packetType);
    writer.writeUint32(version);
    for (final extension in extensions.entries) {
      writer.writeUtf8(extension.key);
      writer.writeUtf8(extension.value);
    }
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SftpInitPacket(version: $version, extensions: $extensions)';
  }
}

class SftpVersionPacket implements SftpPacket {
  static const int packetType = 2;

  final int version;

  final Map<String, String> extensions;

  SftpVersionPacket(this.version, [this.extensions = const {}]);

  factory SftpVersionPacket.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    reader.readUint8(); // packet type
    final version = reader.readUint32();
    final extensions = <String, String>{};
    while (!reader.isDone) {
      final name = reader.readUtf8();
      final value = reader.readUtf8();
      extensions[name] = value;
    }
    return SftpVersionPacket(version, extensions);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(packetType);
    writer.writeUint32(version);
    for (final extension in extensions.entries) {
      writer.writeUtf8(extension.key);
      writer.writeUtf8(extension.value);
    }
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SftpVersionPacket(version: $version, extensions: $extensions)';
  }
}

class SftpOpenPacket implements SftpRequestPacket {
  static const int packetType = 3;

  @override
  final int requestId;

  final String path;

  final int flags;

  final SftpFileAttrs attrs;

  SftpOpenPacket(this.requestId, this.path, this.flags, this.attrs);

  factory SftpOpenPacket.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    reader.readUint8(); // packet type
    final requestId = reader.readUint32();
    final path = reader.readUtf8();
    final flags = reader.readUint32();
    final attrs = SftpFileAttrs.readFrom(reader);
    return SftpOpenPacket(requestId, path, flags, attrs);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(packetType);
    writer.writeUint32(requestId);
    writer.writeUtf8(path);
    writer.writeUint32(flags);
    attrs.writeTo(writer);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SftpOpenPacket(requestId: $requestId, path: $path, flags: $flags, attrs: $attrs)';
  }
}

class SftpClosePacket implements SftpRequestPacket {
  static const int packetType = 4;

  @override
  final int requestId;

  final Uint8List handle;

  SftpClosePacket(this.requestId, this.handle);

  factory SftpClosePacket.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    reader.readUint8(); // packet type
    final requestId = reader.readUint32();
    final handle = reader.readString();
    return SftpClosePacket(requestId, handle);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(packetType);
    writer.writeUint32(requestId);
    writer.writeString(handle);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SftpClosePacket(requestId: $requestId, handle: ${hex.encode(handle)})';
  }
}

class SftpReadPacket implements SftpRequestPacket {
  static const int packetType = 5;

  @override
  final int requestId;

  final Uint8List handle;

  final int offset;

  final int length;

  SftpReadPacket({
    required this.requestId,
    required this.handle,
    required this.offset,
    required this.length,
  });

  factory SftpReadPacket.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    reader.readUint8(); // packet type
    final requestId = reader.readUint32();
    final handle = reader.readString();
    final offset = reader.readUint64();
    final length = reader.readUint32();
    return SftpReadPacket(
        requestId: requestId, handle: handle, offset: offset, length: length);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(packetType);
    writer.writeUint32(requestId);
    writer.writeString(handle);
    writer.writeUint64(offset);
    writer.writeUint32(length);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SftpReadPacket(requestId: $requestId, handle: ${hex.encode(handle)}, offset: $offset, length: $length)';
  }
}

class SftpWritePacket implements SftpRequestPacket {
  static const int packetType = 6;

  @override
  final int requestId;

  final Uint8List handle;

  final int offset;

  final Uint8List data;

  SftpWritePacket({
    required this.requestId,
    required this.handle,
    required this.offset,
    required this.data,
  });

  factory SftpWritePacket.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.readUint8(); // packet type
    final requestId = reader.readUint32();
    final handle = reader.readString();
    final offset = reader.readUint64();
    final data = reader.readString();
    return SftpWritePacket(
      requestId: requestId,
      handle: handle,
      offset: offset,
      data: data,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(packetType);
    writer.writeUint32(requestId);
    writer.writeString(handle);
    writer.writeUint64(offset);
    writer.writeString(data);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SftpWritePacket(requestId: $requestId, handle: ${hex.encode(handle)}, offset: $offset, data.length: ${data.length})';
  }
}

class SftpLStatPacket implements SftpRequestPacket {
  static const int packetType = 7;

  @override
  final int requestId;

  final String path;

  SftpLStatPacket(this.requestId, this.path);

  factory SftpLStatPacket.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    reader.readUint8(); // packet type
    final requestId = reader.readUint32();
    final path = reader.readUtf8();
    return SftpLStatPacket(requestId, path);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(packetType);
    writer.writeUint32(requestId);
    writer.writeUtf8(path);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SftpLStatPacket(requestId: $requestId, path: $path)';
  }
}

class SftpFStatPacket implements SftpRequestPacket {
  static const int packetType = 8;

  @override
  final int requestId;

  final Uint8List handle;

  SftpFStatPacket(this.requestId, this.handle);

  factory SftpFStatPacket.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    reader.readUint8(); // packet type
    final requestId = reader.readUint32();
    final handle = reader.readString();
    return SftpFStatPacket(requestId, handle);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(packetType);
    writer.writeUint32(requestId);
    writer.writeString(handle);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SftpFStatPacket(requestId: $requestId, handle: ${hex.encode(handle)})';
  }
}

class SftpSetStatPacket implements SftpRequestPacket {
  static const int packetType = 9;

  @override
  final int requestId;

  final String path;

  final SftpFileAttrs attributes;

  SftpSetStatPacket(this.requestId, this.path, this.attributes);

  factory SftpSetStatPacket.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    reader.readUint8(); // packet type
    final requestId = reader.readUint32();
    final path = reader.readUtf8();
    final attributes = SftpFileAttrs.readFrom(reader);
    return SftpSetStatPacket(requestId, path, attributes);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(packetType);
    writer.writeUint32(requestId);
    writer.writeUtf8(path);
    attributes.writeTo(writer);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SftpSetStatPacket(requestId: $requestId, path: $path, attributes: $attributes)';
  }
}

class SftpFSetStatPacket implements SftpRequestPacket {
  static const int packetType = 10;

  @override
  final int requestId;

  final Uint8List handle;

  final SftpFileAttrs attributes;

  SftpFSetStatPacket(this.requestId, this.handle, this.attributes);

  factory SftpFSetStatPacket.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    reader.readUint8(); // packet type
    final requestId = reader.readUint32();
    final handle = reader.readString();
    final attributes = SftpFileAttrs.readFrom(reader);
    return SftpFSetStatPacket(requestId, handle, attributes);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(packetType);
    writer.writeUint32(requestId);
    writer.writeString(handle);
    attributes.writeTo(writer);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SftpFSetStatPacket(requestId: $requestId, handle: ${hex.encode(handle)}, attributes: $attributes)';
  }
}

class SftpOpenDirPacket implements SftpRequestPacket {
  static const int packetType = 11;

  @override
  final int requestId;

  final String path;

  SftpOpenDirPacket(this.requestId, this.path);

  factory SftpOpenDirPacket.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    reader.readUint8(); // packet type
    final requestId = reader.readUint32();
    final path = reader.readUtf8();
    return SftpOpenDirPacket(requestId, path);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(packetType);
    writer.writeUint32(requestId);
    writer.writeUtf8(path);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SftpOpenDirPacket(requestId: $requestId, path: $path)';
  }
}

class SftpReadDirPacket implements SftpRequestPacket {
  static const int packetType = 12;

  @override
  final int requestId;

  final Uint8List handle;

  SftpReadDirPacket(this.requestId, this.handle);

  factory SftpReadDirPacket.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    reader.readUint8(); // packet type
    final requestId = reader.readUint32();
    final handle = reader.readString();
    return SftpReadDirPacket(requestId, handle);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(packetType);
    writer.writeUint32(requestId);
    writer.writeString(handle);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SftpReadDirPacket(requestId: $requestId, handle: ${hex.encode(handle)})';
  }
}

class SftpRemovePacket implements SftpRequestPacket {
  static const int packetType = 13;

  @override
  final int requestId;

  final String filename;

  SftpRemovePacket(this.requestId, this.filename);

  factory SftpRemovePacket.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    reader.readUint8(); // packet type
    final requestId = reader.readUint32();
    final path = reader.readUtf8();
    return SftpRemovePacket(requestId, path);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(packetType);
    writer.writeUint32(requestId);
    writer.writeUtf8(filename);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SftpRemovePacket(requestId: $requestId, filename: $filename)';
  }
}

class SftpMkdirPacket implements SftpRequestPacket {
  static const int packetType = 14;

  @override
  final int requestId;

  final String path;

  final SftpFileAttrs attributes;

  SftpMkdirPacket(this.requestId, this.path, this.attributes);

  factory SftpMkdirPacket.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    reader.readUint8(); // packet type
    final requestId = reader.readUint32();
    final path = reader.readUtf8();
    final attributes = SftpFileAttrs.readFrom(reader);
    return SftpMkdirPacket(requestId, path, attributes);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(packetType);
    writer.writeUint32(requestId);
    writer.writeUtf8(path);
    attributes.writeTo(writer);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SftpMkdirPacket(requestId: $requestId, path: $path, attributes: $attributes)';
  }
}

class SftpRmdirPacket implements SftpRequestPacket {
  static const int packetType = 15;

  @override
  final int requestId;

  final String path;

  SftpRmdirPacket(this.requestId, this.path);

  factory SftpRmdirPacket.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    reader.readUint8(); // packet type
    final requestId = reader.readUint32();
    final path = reader.readUtf8();
    return SftpRmdirPacket(requestId, path);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(packetType);
    writer.writeUint32(requestId);
    writer.writeUtf8(path);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SftpRmdirPacket(requestId: $requestId, path: $path)';
  }
}

class SftpRealpathPacket implements SftpRequestPacket {
  static const int packetType = 16;

  @override
  final int requestId;

  final String path;

  SftpRealpathPacket(this.requestId, this.path);

  factory SftpRealpathPacket.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    reader.readUint8(); // packet type
    final requestId = reader.readUint32();
    final path = reader.readUtf8();
    return SftpRealpathPacket(requestId, path);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(packetType);
    writer.writeUint32(requestId);
    writer.writeUtf8(path);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SftpRealpathPacket(requestId: $requestId, path: $path)';
  }
}

class SftpStatPacket implements SftpRequestPacket {
  static const int packetType = 17;

  @override
  final int requestId;

  final String path;

  SftpStatPacket(this.requestId, this.path);

  factory SftpStatPacket.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    reader.readUint8(); // packet type
    final requestId = reader.readUint32();
    final path = reader.readUtf8();
    return SftpStatPacket(requestId, path);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(packetType);
    writer.writeUint32(requestId);
    writer.writeUtf8(path);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SftpStatPacket(requestId: $requestId, path: $path)';
  }
}

class SftpRenamePacket implements SftpRequestPacket {
  static const int packetType = 18;

  @override
  final int requestId;

  final String oldPath;

  final String newPath;

  SftpRenamePacket(this.requestId, this.oldPath, this.newPath);

  factory SftpRenamePacket.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    reader.readUint8(); // packet type
    final requestId = reader.readUint32();
    final oldPath = reader.readUtf8();
    final newPath = reader.readUtf8();
    return SftpRenamePacket(requestId, oldPath, newPath);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(packetType);
    writer.writeUint32(requestId);
    writer.writeUtf8(oldPath);
    writer.writeUtf8(newPath);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SftpRenamePacket(requestId: $requestId, oldPath: $oldPath, newPath: $newPath)';
  }
}

class SftpReadlinkPacket implements SftpRequestPacket {
  static const int packetType = 19;

  @override
  final int requestId;

  final String path;

  SftpReadlinkPacket(this.requestId, this.path);

  factory SftpReadlinkPacket.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    reader.readUint8(); // packet type
    final requestId = reader.readUint32();
    final path = reader.readUtf8();
    return SftpReadlinkPacket(requestId, path);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(packetType);
    writer.writeUint32(requestId);
    writer.writeUtf8(path);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SftpReadlinkPacket(requestId: $requestId, path: $path)';
  }
}

class SftpSymlinkPacket implements SftpRequestPacket {
  static const int packetType = 20;

  @override
  final int requestId;

  final String linkPath;

  final String targetPath;

  SftpSymlinkPacket(this.requestId, this.linkPath, this.targetPath);

  factory SftpSymlinkPacket.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    reader.readUint8(); // packet type
    final requestId = reader.readUint32();
    final linkPath = reader.readUtf8();
    final targetPath = reader.readUtf8();
    return SftpSymlinkPacket(requestId, linkPath, targetPath);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(packetType);
    writer.writeUint32(requestId);
    writer.writeUtf8(linkPath);
    writer.writeUtf8(targetPath);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SftpSymlinkPacket(requestId: $requestId, linkPath: $linkPath, targetPath: $targetPath)';
  }
}

class SftpStatusPacket implements SftpResponsePacket {
  static const int packetType = 101;

  @override
  final int requestId;

  final int code;

  final String message;

  final String language;

  SftpStatusPacket({
    required this.requestId,
    required this.code,
    required this.message,
    this.language = '',
  });

  factory SftpStatusPacket.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    reader.readUint8(); // packet type
    final requestId = reader.readUint32();
    final code = reader.readUint32();
    final message = reader.readUtf8();
    final language = reader.readUtf8();
    return SftpStatusPacket(
      requestId: requestId,
      code: code,
      message: message,
      language: language,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(packetType);
    writer.writeUint32(requestId);
    writer.writeUint32(code);
    writer.writeUtf8(message);
    writer.writeUtf8(language);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SftpStatusPacket(requestId: $requestId, code: $code, message: $message, language: $language)';
  }
}

class SftpHandlePacket implements SftpResponsePacket {
  static const int packetType = 102;

  @override
  final int requestId;

  final Uint8List handle;

  SftpHandlePacket(this.requestId, this.handle);

  factory SftpHandlePacket.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    reader.readUint8(); // packet type
    final requestId = reader.readUint32();
    final handle = reader.readString();
    return SftpHandlePacket(requestId, handle);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(packetType);
    writer.writeUint32(requestId);
    writer.writeString(handle);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SftpHandlePacket(requestId: $requestId, handle: ${hex.encode(handle)})';
  }
}

class SftpDataPacket implements SftpResponsePacket {
  static const int packetType = 103;

  @override
  final int requestId;

  final Uint8List data;

  SftpDataPacket(this.requestId, this.data);

  factory SftpDataPacket.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.readUint8(); // packet type
    final requestId = reader.readUint32();
    final data = reader.readString();
    return SftpDataPacket(requestId, data);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(packetType);
    writer.writeUint32(requestId);
    writer.writeString(data);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SftpDataPacket(requestId: $requestId, data: $data)';
  }
}

class SftpNamePacket implements SftpResponsePacket {
  static const int packetType = 104;

  @override
  final int requestId;

  final List<SftpName> names;

  SftpNamePacket(this.requestId, this.names);

  factory SftpNamePacket.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    reader.readUint8(); // packet type
    final requestId = reader.readUint32();
    final nameCount = reader.readUint32();
    final names = <SftpName>[];
    for (var i = 0; i < nameCount; i++) {
      final name = SftpName.readFrom(reader);
      names.add(name);
    }
    return SftpNamePacket(requestId, names);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(packetType);
    writer.writeUint32(requestId);
    writer.writeUint32(names.length);
    for (final name in names) {
      name.writeTo(writer);
    }
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SftpNamePacket(requestId: $requestId, names: $names)';
  }
}

class SftpAttrsPacket implements SftpResponsePacket {
  static const int packetType = 105;

  @override
  final int requestId;

  final SftpFileAttrs attrs;

  SftpAttrsPacket(this.requestId, this.attrs);

  factory SftpAttrsPacket.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    reader.readUint8(); // packet type
    final requestId = reader.readUint32();
    final attrs = SftpFileAttrs.readFrom(reader);
    return SftpAttrsPacket(requestId, attrs);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(packetType);
    writer.writeUint32(requestId);
    attrs.writeTo(writer);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SftpAttrsPacket(requestId: $requestId, attrs: $attrs)';
  }
}
