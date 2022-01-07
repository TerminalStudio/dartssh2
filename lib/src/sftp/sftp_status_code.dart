abstract class SftpStatusCode {
  /// Indicates successful completion of the operation.
  static const ok = 0;

  /// indicates end-of-file condition; for [SftpReadPacket] it means that no
  /// more data is available in the file, and for [SftpReadDirPacket] it
  /// indicates that no more files are contained in the directory.
  static const eof = 1;

  /// Returned when a reference is made to a file which should exist
  /// but doesn't.
  static const noSuchFile = 2;

  /// Returned when the authenticated user does not have sufficient
  /// permissions to perform the operation.
  static const permissionDenied = 3;

  /// A generic catch-all error message; it should be returned if an
  /// error occurs for which there is no more specific error code
  /// defined.
  static const failure = 4;

  /// may be returned if a badly formatted packet or protocol
  /// incompatibility is detected.
  static const badMessage = 5;

  /// A pseudo-error which indicates that the client has no
  /// connection to the server (it can only be generated locally by the
  /// client, and MUST NOT be returned by servers).
  static const noConnection = 6;

  /// A pseudo-error which indicates that the connection to the
  /// server has been lost (it can only be generated locally by the
  /// client, and MUST NOT be returned by servers).
  static const connectionLost = 7;

  /// Indicates that an attempt was made to perform an operation which
  /// is not supported for the server (it may be generated locally by
  /// the client if e.g.  the version number exchange indicates that a
  /// required feature is not supported by the server, or it may be
  /// returned by the server if the server does not implement an
  /// operation).
  static const opUnsupported = 8;
}
