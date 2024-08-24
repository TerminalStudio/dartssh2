import 'package:dartssh4/src/utils/int.dart';
import 'package:dartssh4/src/ssh_message.dart';

abstract class _Flags {
  static const size = 0x00000001;
  static const uidgid = 0x00000002;
  static const permissions = 0x00000004;
  static const acmodtime = 0x00000008;
  static const extended = 0x80000000;
}

abstract class _PermissionFlags {
  /// 0400
  static const userRead = 1 << 8;

  /// 0200
  static const userWrite = 1 << 7;

  /// 0100
  static const userExecute = 1 << 6;

  /// 0040
  static const groupRead = 1 << 5;

  /// 0020
  static const groupWrite = 1 << 4;

  /// 0010
  static const groupExecute = 1 << 3;

  /// 0004
  static const otherRead = 1 << 2;

  /// 0002
  static const otherWrite = 1 << 1;

  /// 0001
  static const otherExecute = 1 << 0;
}

abstract class _ModeFlags {
  /// 0010000
  static const isPipe = 1 << 12;

  /// 0020000
  static const isCharacterDevice = 1 << 13;

  /// 0040000
  static const isDirectory = 1 << 14;

  /// 0060000
  static const isBlockDevice = (1 << 14) + (1 << 13);

  /// 0100000
  static const isRegularFile = 1 << 15;

  /// 0120000
  static const isSymbolicLink = (1 << 15) + (1 << 13);

  /// 0140000
  static const isSocket = (1 << 15) + (1 << 14);

  /// 0160000
  static const isWhiteout = (1 << 15) + (1 << 14) + (1 << 13);

  /// 0170000
  static const mask = (1 << 15) + (1 << 14) + (1 << 13) + (1 << 12);
}

extension _IntFlag on int {
  bool has(int flag) => (this & flag) == flag;
}

enum SftpFileType {
  unknown,
  regularFile,
  directory,
  symbolicLink,
  blockDevice,
  characterDevice,
  pipe,
  socket,
  whiteout,
}

class SftpFileMode {
  factory SftpFileMode({
    bool userRead = true,
    bool userWrite = true,
    bool userExecute = true,
    bool groupRead = true,
    bool groupWrite = true,
    bool groupExecute = true,
    bool otherRead = true,
    bool otherWrite = true,
    bool otherExecute = true,
  }) {
    var flags = 0;
    if (userRead) flags |= _PermissionFlags.userRead;
    if (userWrite) flags |= _PermissionFlags.userWrite;
    if (userExecute) flags |= _PermissionFlags.userExecute;
    if (groupRead) flags |= _PermissionFlags.groupRead;
    if (groupWrite) flags |= _PermissionFlags.groupWrite;
    if (groupExecute) flags |= _PermissionFlags.groupExecute;
    if (otherRead) flags |= _PermissionFlags.otherRead;
    if (otherWrite) flags |= _PermissionFlags.otherWrite;
    if (otherExecute) flags |= _PermissionFlags.otherExecute;
    return SftpFileMode.value(flags);
  }

  const SftpFileMode.value(this.value);

  final int value;

  bool get userRead => value.has(_PermissionFlags.userRead);
  bool get userWrite => value.has(_PermissionFlags.userWrite);
  bool get userExecute => value.has(_PermissionFlags.userExecute);

  bool get groupRead => value.has(_PermissionFlags.groupRead);
  bool get groupWrite => value.has(_PermissionFlags.groupWrite);
  bool get groupExecute => value.has(_PermissionFlags.groupExecute);

  bool get otherRead => value.has(_PermissionFlags.otherRead);
  bool get otherWrite => value.has(_PermissionFlags.otherWrite);
  bool get otherExecute => value.has(_PermissionFlags.otherExecute);

  SftpFileType get type {
    var type = value & _ModeFlags.mask;
    switch (type) {
      case _ModeFlags.isPipe:
        return SftpFileType.pipe;
      case _ModeFlags.isCharacterDevice:
        return SftpFileType.characterDevice;
      case _ModeFlags.isDirectory:
        return SftpFileType.directory;
      case _ModeFlags.isBlockDevice:
        return SftpFileType.blockDevice;
      case _ModeFlags.isRegularFile:
        return SftpFileType.regularFile;
      case _ModeFlags.isSymbolicLink:
        return SftpFileType.symbolicLink;
      case _ModeFlags.isSocket:
        return SftpFileType.socket;
      case _ModeFlags.isWhiteout:
        return SftpFileType.whiteout;
      default:
        return SftpFileType.unknown;
    }
  }

  @override
  String toString() {
    return '$runtimeType(${value.toOctal()})';
  }
}

class SftpFileAttrs {
  /// The size of the file in bytes.
  final int? size;

  /// The user ID of the file.
  final int? userID;

  /// The group ID of the file.
  final int? groupID;

  /// The mode of the file, including file type and permissions.
  final SftpFileMode? mode;

  /// The access time of the file in seconds since the epoch.
  final int? accessTime;

  /// The modification time of the file in seconds since the epoch.
  final int? modifyTime;

  /// The extended attributes of the file.
  final Map<String, String>? extended;

  SftpFileAttrs({
    this.size,
    this.userID,
    this.groupID,
    this.mode,
    this.accessTime,
    this.modifyTime,
    this.extended,
  });

  factory SftpFileAttrs.readFrom(SSHMessageReader reader) {
    final flags = reader.readUint32();
    final size = flags.has(_Flags.size) ? reader.readUint64() : null;
    final uid = flags.has(_Flags.uidgid) ? reader.readUint32() : null;
    final gid = flags.has(_Flags.uidgid) ? reader.readUint32() : null;
    final perms = flags.has(_Flags.permissions) ? reader.readUint32() : null;
    final atime = flags.has(_Flags.acmodtime) ? reader.readUint32() : null;
    final mtime = flags.has(_Flags.acmodtime) ? reader.readUint32() : null;

    final extended = flags.has(_Flags.extended) ? <String, String>{} : null;
    if (extended != null) {
      final count = reader.readUint32();
      for (var i = 0; i < count; i++) {
        final key = reader.readUtf8();
        final value = reader.readUtf8();
        extended[key] = value;
      }
    }

    return SftpFileAttrs(
      size: size,
      userID: uid,
      groupID: gid,
      mode: perms != null ? SftpFileMode.value(perms) : null,
      accessTime: atime,
      modifyTime: mtime,
      extended: extended,
    );
  }

  /// Whether the file is a regular file. See [type].
  bool get isDirectory => mode?.type == SftpFileType.directory;

  /// Whether the file is a symbolic link. See [type].
  bool get isFile => mode?.type == SftpFileType.regularFile;

  /// Whether the file is a symbolic link. See [type].
  bool get isSymbolicLink => mode?.type == SftpFileType.symbolicLink;

  /// Whether the file is a block device. See [type].
  bool get isBlockDevice => mode?.type == SftpFileType.blockDevice;

  /// Whether the file is a character device. See [type].
  bool get isCharacterDevice => mode?.type == SftpFileType.characterDevice;

  /// Whether the file is a pipe. See [type].
  bool get isPipe => mode?.type == SftpFileType.pipe;

  /// Whether the file is a socket. See [type].
  bool get isSocket => mode?.type == SftpFileType.socket;

  /// Whether the file is a whiteout. See [type].
  bool get isWhiteout => mode?.type == SftpFileType.whiteout;

  /// Shortcut for [mode]?.type
  SftpFileType? get type => mode?.type;

  void writeTo(SSHMessageWriter writer) {
    var flags = 0;
    if (size != null) flags |= _Flags.size;
    if (userID != null) flags |= _Flags.uidgid;
    if (groupID != null) flags |= _Flags.uidgid;
    if (mode != null) flags |= _Flags.permissions;
    if (accessTime != null) flags |= _Flags.acmodtime;
    if (modifyTime != null) flags |= _Flags.acmodtime;
    if (extended != null) flags |= _Flags.extended;

    writer.writeUint32(flags);
    if (size != null) writer.writeUint64(size!);
    if (userID != null) writer.writeUint32(userID!);
    if (groupID != null) writer.writeUint32(groupID!);
    if (mode != null) writer.writeUint32(mode!.value);
    if (accessTime != null) writer.writeUint32(accessTime!);
    if (modifyTime != null) writer.writeUint32(modifyTime!);

    if (extended != null) {
      writer.writeUint32(extended!.length);
      for (var pair in extended!.entries) {
        writer.writeUtf8(pair.key);
        writer.writeUtf8(pair.value);
      }
    }
  }

  @override
  String toString() {
    final props = <String>[];
    if (size != null) props.add('size: $size');
    if (userID != null) props.add('uid: $userID');
    if (groupID != null) props.add('gid: $groupID');
    if (mode != null) props.add('mode: otc($mode)');
    if (accessTime != null) props.add('atime: $accessTime');
    if (modifyTime != null) props.add('mtime: $modifyTime');
    if (extended != null) props.add('extended: $extended');
    return 'SftpFileAttrs(${props.join(', ')})';
  }
}
