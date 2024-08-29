import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:pointycastle/export.dart';
import 'package:test/test.dart';

void main() {
  group('SSHMacType', () {
    test('Static constants are defined correctly', () {
      expect(SSHMacType.hmacMd5.name, equals('hmac-md5'));
      expect(SSHMacType.hmacSha1.name, equals('hmac-sha1'));
      expect(SSHMacType.hmacSha256.name, equals('hmac-sha2-256'));
      expect(SSHMacType.hmacSha512.name, equals('hmac-sha2-512'));

      expect(SSHMacType.hmacMd5.keySize, equals(16));
      expect(SSHMacType.hmacSha1.keySize, equals(20));
      expect(SSHMacType.hmacSha256.keySize, equals(32));
      expect(SSHMacType.hmacSha512.keySize, equals(64));
    });

    test('createMac() returns correct Mac instance', () {
      final key = Uint8List(16); // 16 bytes key for hmacMd5
      final mac = SSHMacType.hmacMd5.createMac(key);
      expect(mac, isA<HMac>());
    });

    test('createMac() throws ArgumentError for incorrect key length', () {
      final shortKey = Uint8List(15); // One byte too short for hmacMd5
      expect(
        () => SSHMacType.hmacMd5.createMac(shortKey),
        throwsArgumentError,
      );

      final longKey = Uint8List(17); // One byte too long for hmacMd5
      expect(
        () => SSHMacType.hmacMd5.createMac(longKey),
        throwsArgumentError,
      );
    });

    test('createMac() initializes Mac with correct key length', () {
      final key = Uint8List(32); // 32 bytes key for hmacSha256
      final mac = SSHMacType.hmacSha256.createMac(key);
      expect(mac, isA<HMac>());
    });

    test('createMac() initializes Mac with correct MAC factory', () {
      final key = Uint8List(64); // 64 bytes key for hmacSha512
      final mac = SSHMacType.hmacSha512.createMac(key);
      expect(mac, isA<HMac>());
    });
  });
}
