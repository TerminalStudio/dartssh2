import 'package:dartssh2/src/sftp/sftp_packet_ext.dart';

/// Information about the file system. Corresponds to the `statvfs` system call
/// on POSIX systems.
class SftpStatVfs {
  SftpStatVfs({
    required this.blockSize,
    required this.fundamentalBlockSize,
    required this.totalBlocks,
    required this.freeBlocks,
    required this.freeBlocksForNonRoot,
    required this.totalInodes,
    required this.freeInodes,
    required this.freeInodesForNonRoot,
    required this.fileSystemId,
    required this.isReadOnly,
    required this.isNoSuid,
    required this.maximumFilenameLength,
  });

  factory SftpStatVfs.fromReply(SftpStatVfsReply reply) {
    const statVfsFlagReadOnly = 0x01;
    const statVfsFlagNoSuid = 0x02;

    return SftpStatVfs(
      blockSize: reply.blockSize,
      fundamentalBlockSize: reply.fundamentalBlockSize,
      totalBlocks: reply.totalBlocks,
      freeBlocks: reply.freeBlocks,
      freeBlocksForNonRoot: reply.freeBlocksForNonRoot,
      totalInodes: reply.totalInodes,
      freeInodes: reply.freeInodes,
      freeInodesForNonRoot: reply.freeInodesForNonRoot,
      fileSystemId: reply.fileSystemId,
      isReadOnly: reply.flag & statVfsFlagReadOnly != 0,
      isNoSuid: reply.flag & statVfsFlagNoSuid != 0,
      maximumFilenameLength: reply.maximumFilenameLength,
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

  /// Whether the file system is read-only.
  final bool isReadOnly;

  /// Whether the file system supports the setuid and setgid file mode bits.
  final bool isNoSuid;

  /// maximum filename length
  final int maximumFilenameLength;

  @override
  String toString() {
    return 'SftpStatVfs{'
        'blockSize: $blockSize, '
        'fundamentalBlockSize: $fundamentalBlockSize, '
        'totalBlocks: $totalBlocks, '
        'freeBlocks: $freeBlocks, '
        'freeBlocksForNonRoot: $freeBlocksForNonRoot, '
        'totalInodes: $totalInodes, '
        'freeInodes: $freeInodes, '
        'freeInodesForNonRoot: $freeInodesForNonRoot, '
        'fileSystemId: $fileSystemId, '
        'isReadOnly: $isReadOnly, '
        'isNoSuid: $isNoSuid, '
        'maximumFilenameLength: $maximumFilenameLength'
        '}';
  }
}
