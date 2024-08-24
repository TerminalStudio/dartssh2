import 'package:dartssh4/src/sftp/sftp_packet.dart';
import 'package:dartssh4/src/sftp/sftp_status_code.dart';

class SftpError {
  final String message;

  SftpError(this.message);

  @override
  String toString() {
    return 'SftpError: $message';
  }
}

class SftpAbortError implements SftpError {
  @override
  final String message;

  SftpAbortError(this.message);

  @override
  String toString() {
    return 'SftpAbortError: $message';
  }
}

class SftpStatusError implements SftpError {
  final int code;

  @override
  final String message;

  SftpStatusError(this.code, this.message);

  SftpStatusError.fromStatus(SftpStatusPacket status)
      : code = status.code,
        message = status.message;

  static void check(SftpStatusPacket status) {
    if (status.code != SftpStatusCode.ok && status.code != SftpStatusCode.eof) {
      throw SftpStatusError.fromStatus(status);
    }
  }

  @override
  String toString() {
    return 'SftpStatusError: $message(code $code)';
  }
}

/* sealed */ abstract class SftpExtensionError implements SftpError {}

class SftpExtensionUnsupportedError implements SftpExtensionError {
  final String extension;

  @override
  String get message => 'Extension "$extension" is not supported';

  SftpExtensionUnsupportedError(this.extension);

  @override
  String toString() {
    return 'SftpExtensionUnsupportedError: $message';
  }
}

class SftpExtensionVersionMismatchError implements SftpExtensionError {
  final String extension;

  final String version;

  @override
  String get message =>
      'Extension "$extension" of version $version is not supported';

  SftpExtensionVersionMismatchError(this.extension, this.version);

  @override
  String toString() {
    return 'SftpExtensionVersionMismatchError: $message';
  }
}
