import 'dart:typed_data';

import 'package:dartssh4/src/sftp/sftp_packet.dart';
import 'package:dartssh4/src/ssh_message.dart';

/// Represents the payload of an extended request. Should be wrapped in a
/// [SftpExtendedPacket] before being sent.
abstract class SftpExtendedRequest {
  /// The name to identify the extended request.
  ///
  /// This string is encoded as the first field of the extended request body.
  String get name;

  /// Writes the extended request body to the [writer].
  void writeTo(SSHMessageWriter writer);

  /// Encodes the extended request body including the name.
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUtf8(name);
    writeTo(writer);
    return writer.takeBytes();
  }
}

/// Represents the payload of an extended reply. Should be wrapped in a
/// [SftpExtendedReplyPacket] before being sent.
abstract class SftpExtendedReply {}

/// This request correspond to the statvfs POSIX system interface.
class SftpStatVfsRequest extends SftpExtendedRequest {
  SftpStatVfsRequest({required this.path});

  @override
  final String name = 'statvfs@openssh.com';

  final String path;

  @override
  void writeTo(SSHMessageWriter writer) {
    writer.writeUtf8(path);
  }
}

/// This request correspond to the fstatvfs POSIX system interface.
class SftpFstatVfsRequest extends SftpExtendedRequest {
  SftpFstatVfsRequest({required this.handle});

  @override
  final String name = 'fstatvfs@openssh.com';

  final Uint8List handle;

  @override
  void writeTo(SSHMessageWriter writer) {
    writer.writeString(handle);
  }
}

/// uint64		f_bsize		/* file system block size */
/// uint64		f_frsize	/* fundamental fs block size */
/// uint64		f_blocks	/* number of blocks (unit f_frsize) */
/// uint64		f_bfree		/* free blocks in file system */
/// uint64		f_bavail	/* free blocks for non-root */
/// uint64		f_files		/* total file inodes */
/// uint64		f_ffree		/* free file inodes */
/// uint64		f_favail	/* free file inodes for to non-root */
/// uint64		f_fsid		/* file system id */
/// uint64		f_flag		/* bit mask of f_flag values */
/// uint64		f_namemax	/* maximum filename length */
class SftpStatVfsReply {
  SftpStatVfsReply({
    required this.blockSize,
    required this.fundamentalBlockSize,
    required this.totalBlocks,
    required this.freeBlocks,
    required this.freeBlocksForNonRoot,
    required this.totalInodes,
    required this.freeInodes,
    required this.freeInodesForNonRoot,
    required this.fileSystemId,
    required this.flag,
    required this.maximumFilenameLength,
  });

  factory SftpStatVfsReply.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    return SftpStatVfsReply(
      blockSize: reader.readUint64(),
      fundamentalBlockSize: reader.readUint64(),
      totalBlocks: reader.readUint64(),
      freeBlocks: reader.readUint64(),
      freeBlocksForNonRoot: reader.readUint64(),
      totalInodes: reader.readUint64(),
      freeInodes: reader.readUint64(),
      freeInodesForNonRoot: reader.readUint64(),
      fileSystemId: reader.readUint64(),
      flag: reader.readUint64(),
      maximumFilenameLength: reader.readUint64(),
    );
  }

  /// file system block size
  final int blockSize;

  /// fundamental fs block size
  final int fundamentalBlockSize;

  /// number of blocks (unit f_frsize)
  final int totalBlocks;

  /// free blocks in file system
  final int freeBlocks;

  /// free blocks for non-root
  final int freeBlocksForNonRoot;

  /// total file inodes
  final int totalInodes;

  /// free file inodes
  final int freeInodes;

  /// free file inodes for to non-root
  final int freeInodesForNonRoot;

  /// file system id
  final int fileSystemId;

  /// bit mask of f_flag values
  final int flag;

  /// maximum filename length
  final int maximumFilenameLength;
}
