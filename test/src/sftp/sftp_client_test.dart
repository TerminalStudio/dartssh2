import 'package:dartssh2/dartssh2.dart';
import 'package:test/test.dart';

import '../../test_utils.dart';

void main() {
  group('SftpClient.statVFS', () {
    test('throws if the extension is not supported by the server', () async {
      final client = await getTestClient();
      final sftp = await client.sftp();
      expect(() => sftp.statvfs('/root'), throwsA(isA<SftpExtensionError>()));
    });
  });

  group('SftpFile.statVFS', () {
    test('throws if the extension is not supported by the server', () async {
      final client = await getTestClient();
      final sftp = await client.sftp();
      expect(() => sftp.statvfs('/root/a'), throwsA(isA<SftpExtensionError>()));
    });
  });
}
