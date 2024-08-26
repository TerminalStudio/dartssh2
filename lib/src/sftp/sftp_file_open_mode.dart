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

  /// Internal integer flag representing the file open mode.
  final int flag;

  /// Private constructor used to create instances of [SftpFileOpenMode] with specific flags.
  ///
  /// This constructor is marked as private (`._`) to restrict direct instantiation and ensure
  /// that only predefined modes like [read], [write], etc., can be used.
  const SftpFileOpenMode._(this.flag);

  /// Overloads the bitwise OR operator `|` for the `SftpFileOpenMode` class.
  ///
  /// This operator allows combining two `SftpFileOpenMode` instances by performing
  /// a bitwise OR operation on their respective flags. The result is a new
  /// `SftpFileOpenMode` instance that represents the combined flags of both modes.
  ///
  /// Example:
  /// ```dart
  /// SftpFileOpenMode readMode = SftpFileOpenMode.read;
  /// SftpFileOpenMode writeMode = SftpFileOpenMode.write;
  ///
  /// SftpFileOpenMode combinedMode = readMode | writeMode;
  /// ```
  ///
  /// In the example above, the `combinedMode` will contain the flags of both
  /// `readMode` and `writeMode`.
  ///
  /// - Parameter [other]: Another instance of `SftpFileOpenMode` to combine with.
  /// - Returns: A new `SftpFileOpenMode` instance containing the combined flags.
  SftpFileOpenMode operator |(SftpFileOpenMode other) =>
      SftpFileOpenMode._(flag | other.flag);
}
