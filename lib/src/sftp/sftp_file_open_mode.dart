class SftpFileOpenMode {
  /// Open the file for reading.
  static const read = SftpFileOpenMode._(1 << 0);

  /// Open the file for writing.
  /// If both this and [read] are specified, the file is opened for both reading
  /// and writing.
  static const write = SftpFileOpenMode._(1 << 1);

  /// Force all writes to append data at the end of the file.
  static const append = SftpFileOpenMode._(1 << 2);

  /// If this flag is specified, then a new file will be created if one
  /// does not already exist (if [truncate] is specified, the new file will
  /// be truncated to zero length if it previously exists).
  static const create = SftpFileOpenMode._(1 << 3);

  /// Forces an existing file with the same name to be truncated to zero
  /// length when creating a file by specifying [create]. [create] MUST also be
  /// specified if this flag is used.
  static const truncate = SftpFileOpenMode._(1 << 4);

  /// Causes the request to fail if the named file already exists.
  /// [create] MUST also be specified if this flag is used.
  static const exclusive = SftpFileOpenMode._(1 << 5);

  final int flag;

  const SftpFileOpenMode._(this.flag);

  operator |(SftpFileOpenMode other) => SftpFileOpenMode._(flag | other.flag);
}
