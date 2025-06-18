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
      // Added new algorithms
      expect(SSHMacType.hmacSha256_96.name, equals('hmac-sha2-256-96'));
      expect(SSHMacType.hmacSha512_96.name, equals('hmac-sha2-512-96'));
      expect(SSHMacType.hmacSha256Etm.name, equals('hmac-sha2-256-etm@openssh.com'));
      expect(SSHMacType.hmacSha512Etm.name, equals('hmac-sha2-512-etm@openssh.com'));

      expect(SSHMacType.hmacMd5.keySize, equals(16));
      expect(SSHMacType.hmacSha1.keySize, equals(20));
      expect(SSHMacType.hmacSha256.keySize, equals(32));
      expect(SSHMacType.hmacSha512.keySize, equals(64));
      // Added new algorithm key sizes
      expect(SSHMacType.hmacSha256_96.keySize, equals(32));
      expect(SSHMacType.hmacSha512_96.keySize, equals(64));
      expect(SSHMacType.hmacSha256Etm.keySize, equals(32));
      expect(SSHMacType.hmacSha512Etm.keySize, equals(64));
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

    test('createMac() for new algorithm types returns correct instances', () {
      final sha256Key = Uint8List(32); // 32 bytes for SHA-256 based algorithms
      final sha512Key = Uint8List(64); // 64 bytes for SHA-512 based algorithms

      final macSha256_96 = SSHMacType.hmacSha256_96.createMac(sha256Key);
      final macSha512_96 = SSHMacType.hmacSha512_96.createMac(sha512Key);
      final macSha256Etm = SSHMacType.hmacSha256Etm.createMac(sha256Key);
      final macSha512Etm = SSHMacType.hmacSha512Etm.createMac(sha512Key);

      expect(macSha256_96, isNotNull);
      expect(macSha512_96, isNotNull);
      expect(macSha256Etm, isA<HMac>());
      expect(macSha512Etm, isA<HMac>());
    });

    test('createMac() throws for new algorithms with incorrect key length', () {
      final shortSha256Key = Uint8List(31); // One byte too short for SHA-256 based algorithms
      final shortSha512Key = Uint8List(63); // One byte too short for SHA-512 based algorithms

      expect(
        () => SSHMacType.hmacSha256_96.createMac(shortSha256Key),
        throwsArgumentError,
      );

      expect(
        () => SSHMacType.hmacSha512_96.createMac(shortSha512Key),
        throwsArgumentError,
      );

      expect(
        () => SSHMacType.hmacSha256Etm.createMac(shortSha256Key),
        throwsArgumentError,
      );

      expect(
        () => SSHMacType.hmacSha512Etm.createMac(shortSha512Key),
        throwsArgumentError,
      );
    });
  });
}
