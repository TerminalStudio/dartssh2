@Tags(['integration'])
library;

import 'dart:io';

import 'package:dartssh2/dartssh2.dart';
import 'package:test/test.dart';

import '../../test_utils.dart';

void main() {
  late SSHClient client;

  setUp(() async {
    client = await getTestClient();
  });

  tearDown(() async {
    client.close();
    await client.done;
  });

  group('SftpClient.listdir', () {
    test('lists root directory with / path', () async {
      final sftp = await client.sftp();

      final items = await sftp.listdir('/');

      expect(items, isNotEmpty);
      expect(items.any((item) => item.filename == '.'), isTrue);
    });
  });

  group('SftpClient.statVFS', () {
    test('throws if the extension is not supported by the server', () async {
      final sftp = await client.sftp();
      expect(() => sftp.statvfs('/root'), throwsA(isA<SftpExtensionError>()));
    });
  });

  group('SftpFile.statVFS', () {
    test('throws if the extension is not supported by the server', () async {
      final sftp = await client.sftp();
      expect(() => sftp.statvfs('/root/a'), throwsA(isA<SftpExtensionError>()));
    });
  });

  group('SftpClient.download', () {
    test('downloads a remote file to local sink', () async {
      final sftp = await client.sftp();
      final items = await sftp.listdir('/');
      final firstFile = items.firstWhere(
        (item) =>
            item.filename != '.' && item.filename != '..' && item.attr.isFile,
      );

      final remotePath = '/${firstFile.filename}';
      final remoteAttrs = await sftp.stat(remotePath);

      final outputFile = File(
        '${Directory.systemTemp.path}/dartssh2_download_${DateTime.now().microsecondsSinceEpoch}.bin',
      );
      final sink = outputFile.openWrite();

      try {
        final downloadedBytes = await sftp.download(
          remotePath,
          sink,
          closeDestination: true,
        );

        final localBytes = await outputFile.readAsBytes();
        expect(downloadedBytes, localBytes.length);
        expect(localBytes, isNotEmpty);

        if (remoteAttrs.size != null) {
          expect(downloadedBytes, remoteAttrs.size);
        }
      } finally {
        if (await outputFile.exists()) {
          await outputFile.delete();
        }
      }
    });

    test('supports offset and length for partial downloads', () async {
      final sftp = await client.sftp();
      final items = await sftp.listdir('/');
      final firstFile = items.firstWhere(
        (item) =>
            item.filename != '.' && item.filename != '..' && item.attr.isFile,
      );

      final remotePath = '/${firstFile.filename}';
      final file = await sftp.open(remotePath);

      const offset = 5;
      const length = 16;
      final expected = await file.readBytes(length: length, offset: offset);

      final outputFile = File(
        '${Directory.systemTemp.path}/dartssh2_download_partial_${DateTime.now().microsecondsSinceEpoch}.bin',
      );
      final sink = outputFile.openWrite();

      try {
        final downloadedBytes = await file.downloadTo(
          sink,
          offset: offset,
          length: length,
          closeDestination: true,
        );

        final actual = await outputFile.readAsBytes();
        expect(downloadedBytes, expected.length);
        expect(actual, expected);
      } finally {
        await file.close();
        if (await outputFile.exists()) {
          await outputFile.delete();
        }
      }
    });
  });
}
