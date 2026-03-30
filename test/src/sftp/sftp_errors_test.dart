import 'package:dartssh2/src/sftp/sftp_errors.dart';
import 'package:dartssh2/src/sftp/sftp_packet.dart';
import 'package:dartssh2/src/sftp/sftp_status_code.dart';
import 'package:test/test.dart';

void main() {
  group('SftpError types', () {
    test('toString includes message details', () {
      expect(SftpError('oops').toString(), 'SftpError: oops');
      expect(SftpAbortError('abort').toString(), 'SftpAbortError: abort');
      expect(
        SftpExtensionUnsupportedError('posix-rename@openssh.com').toString(),
        contains('not supported'),
      );
      expect(
        SftpExtensionVersionMismatchError('copy-data', '2').toString(),
        contains('version 2'),
      );
    });

    test('SftpStatusError.fromStatus maps code and message', () {
      final status = SftpStatusPacket(
        requestId: 1,
        code: SftpStatusCode.permissionDenied,
        message: 'denied',
      );

      final error = SftpStatusError.fromStatus(status);

      expect(error.code, SftpStatusCode.permissionDenied);
      expect(error.message, 'denied');
      expect(error.toString(),
          contains('code ${SftpStatusCode.permissionDenied}'));
    });

    test('SftpStatusError.check allows ok and eof', () {
      expect(
        () => SftpStatusError.check(
          SftpStatusPacket(
            requestId: 1,
            code: SftpStatusCode.ok,
            message: 'ok',
          ),
        ),
        returnsNormally,
      );

      expect(
        () => SftpStatusError.check(
          SftpStatusPacket(
            requestId: 2,
            code: SftpStatusCode.eof,
            message: 'eof',
          ),
        ),
        returnsNormally,
      );
    });

    test('SftpStatusError.check throws for non-ok status', () {
      expect(
        () => SftpStatusError.check(
          SftpStatusPacket(
            requestId: 3,
            code: SftpStatusCode.failure,
            message: 'failed',
          ),
        ),
        throwsA(
          isA<SftpStatusError>()
              .having((e) => e.code, 'code', SftpStatusCode.failure)
              .having((e) => e.message, 'message', 'failed'),
        ),
      );
    });
  });
}
