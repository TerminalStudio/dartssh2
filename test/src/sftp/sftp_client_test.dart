import 'package:dartssh3/dartssh3.dart';
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
      final file = await sftp.open('/root/a', mode: SftpFileOpenMode.create);
      expect(() => file.statvfs(), throwsA(isA<SftpExtensionError>()));
    });
  });
}
