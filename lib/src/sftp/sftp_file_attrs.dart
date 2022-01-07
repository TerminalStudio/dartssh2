import 'package:dartssh2/src/utils/int.dart';
import 'package:dartssh2/src/ssh_message.dart';
import 'package:dartssh2/src/utils/string.dart';

abstract class _Flags {
  static const size = 0x00000001;
  static const uidgid = 0x00000002;
  static const permissions = 0x00000004;
  static const acmodtime = 0x00000008;
  static const extended = 0x80000000;
}

extension _IntFlag on int {
  bool has(int flag) => (this & flag) == flag;
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
    if (userRead) flags |= 0x4 << 6;
    if (userWrite) flags |= 0x2 << 6;
    if (userExecute) flags |= 0x1 << 6;
    if (groupRead) flags |= 0x4 << 3;
    if (groupWrite) flags |= 0x2 << 3;
    if (groupExecute) flags |= 0x1 << 3;
    if (otherRead) flags |= 0x4;
    if (otherWrite) flags |= 0x2;
    if (otherExecute) flags |= 0x1;
    return SftpFileMode.value(flags);
  }

  const SftpFileMode.value(this.value);

  final int value;

  bool get userRead => value & '0400'.octal == '0400'.octal;
  bool get userWrite => value & '0200'.octal == '0200'.octal;
  bool get userExecute => value & '0100'.octal == '0100'.octal;

  bool get groupRead => value & '0040'.octal == '0040'.octal;
  bool get groupWrite => value & '0020'.octal == '0020'.octal;
  bool get groupExecute => value & '0010'.octal == '0010'.octal;

  bool get otherRead => value & '0004'.octal == '0004'.octal;
  bool get otherWrite => value & '0002'.octal == '0002'.octal;
  bool get otherExecute => value & '0001'.octal == '0001'.octal;

  bool get isNamedPipe => value & '0100000'.octal == '0100000'.octal;
  bool get isCharacterDevice => value & '020000'.octal == '020000'.octal;
  bool get isDirectory => value & '040000'.octal == '040000'.octal;
  bool get isBlockDevice => value & '060000'.octal == '060000'.octal;
  bool get isRegularFile => value & '0100000'.octal == '0100000'.octal;
  bool get isSymbolicLink => value & '0120000'.octal == '0120000'.octal;
  bool get isSocket => value & '0140000'.octal == '0140000'.octal;
  bool get isWhiteout => value & '0160000'.octal == '0160000'.octal;

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
