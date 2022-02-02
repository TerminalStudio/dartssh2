import 'package:dartssh2/src/sftp/sftp_packet.dart';
import 'package:dartssh2/src/sftp/sftp_status_code.dart';

class SftpError {
  final String message;

  SftpError(this.message);

  @override
  String toString() {
    return '$runtimeType: $message';
  }
}

class SftpAbortError implements SftpError {
  @override
  final String message;

  SftpAbortError(this.message);

  @override
  String toString() {
    return '$runtimeType: $message';
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
    return '$runtimeType: $message(code $code)';
  }
}
