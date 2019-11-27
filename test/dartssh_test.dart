// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:test/test.dart';

import 'package:dartssh/identity.dart';
import 'package:dartssh/pem.dart';
import 'package:dartssh/protocol.dart';
import 'package:dartssh/serializable.dart';
import 'package:dartssh/ssh.dart';

import '../example/dartssh.dart' as ssh;
import '../example/dartsshd.dart' as sshd;

void main() {
  /// https://www.ietf.org/rfc/rfc4251.txt
  test('mpint', () {
    Uint8List buffer = Uint8List(4096);
    SerializableInput input = SerializableInput(buffer, endian: Endian.big);
    SerializableOutput output = SerializableOutput(buffer, endian: Endian.big);

    BigInt x = BigInt.from(0);
    serializeMpInt(output, x);
    expect(hex.encode(output.view()), '00000000');
    expect(deserializeMpInt(input), x);
    expect(input.offset, output.offset);

    x = (BigInt.from(0x9a378f9) << 32) | BigInt.from(0xb2e332a7);
    input.offset = output.offset = 0;
    serializeMpInt(output, x);
    expect(hex.encode(output.view()), '0000000809a378f9b2e332a7');
    expect(deserializeMpInt(input), x);
    expect(input.offset, output.offset);

    x = BigInt.from(0x80);
    input.offset = output.offset = 0;
    serializeMpInt(output, x);
    expect(hex.encode(output.view()), '000000020080');
    expect(deserializeMpInt(input), x);
    expect(input.offset, output.offset);
  });

  test('pem', () {
    Identity rsa1 = parsePem(File('test/id_rsa').readAsStringSync());
    Identity rsa2 = parsePem(File('test/id_rsa.openssh').readAsStringSync());
    expect(rsa1.rsaPublic.exponent, rsa2.rsaPublic.exponent);
  });

  test('suite', () async {
    int kexIndex = 1, keyIndex = 1, cipherIndex = 1, macIndex = 1;
    bool kexLooped = false,
        keyLooped = false,
        cipherLooped = false,
        macLooped = false;
    KEX.supported = (int id) => id == kexIndex;
    Key.supported = (int id) => id == keyIndex;
    Cipher.supported = (int id) => id == cipherIndex;
    MAC.supported = (int id) => id == macIndex;
    while (!kexLooped || !keyLooped || !cipherLooped || !macLooped) {
      print(
          '=== suite begin ${KEX.name(kexIndex)}, ${Key.name(keyIndex)}, ${Cipher.name(cipherIndex)}, ${MAC.name(macIndex)} ===');

      StreamController<List<int>> sshInput = StreamController<List<int>>();
      String sshResponse = '', identityFile;

      switch (keyIndex) {
        case Key.ED25519:
          identityFile = 'test/id_ed25519';
          break;
        case Key.ECDSA_SHA2_NISTP256:
          identityFile = 'test/id_ecdsa';
          break;
        case Key.ECDSA_SHA2_NISTP384:
          identityFile = 'test/ecdsa-sha2-nistp384/id_ecdsa';
          break;
        case Key.ECDSA_SHA2_NISTP521:
          identityFile = 'test/ecdsa-sha2-nistp521/id_ecdsa';
          break;
        case Key.RSA:
          identityFile = 'test/id_rsa';
          break;
        default:
          throw FormatException('key $keyIndex');
      }

      Future<void> sshdMain = sshd.sshd(<String>[
        '-p 42022',
        '-h',
        (keyIndex == Key.ECDSA_SHA2_NISTP384 ||
                keyIndex == Key.ECDSA_SHA2_NISTP521)
            ? 'test/${Key.name(keyIndex)}/ssh_host_'
            : 'test/ssh_host_',
        '--debug',
        '1',
        '--trace',
        '1'
      ]);

      Future<void> sshMain = ssh.ssh(<String>[
        '-l',
        'root',
        '127.0.0.1:42022',
        '-i',
        identityFile,
        '--debug',
        '1',
        '--trace',
        '1'
      ], sshInput.stream, (_, String v) => sshResponse += v,
          () => sshInput.close());

      while (ssh.client.sessionChannel == null) {
        await Future.delayed(const Duration(seconds: 1));
      }
      ssh.client.sendChannelData(utf8.encode('exit\n'));
      await sshMain;
      await sshdMain;
      expect(sshResponse, '\$ exit\n');

      print(
          '=== suite end ${KEX.name(kexIndex)}, ${Key.name(keyIndex)}, ${Cipher.name(cipherIndex)}, ${MAC.name(macIndex)} ===');
      kexIndex++;
      if (kexIndex > KEX.End) {
        kexLooped = true;
        kexIndex = 1;
      }
      keyIndex++;
      if (keyIndex > Key.End) {
        keyLooped = true;
        keyIndex = 1;
      }
      cipherIndex++;
      if (cipherIndex > Cipher.End) {
        cipherLooped = true;
        cipherIndex = 1;
      }
      macIndex++;
      if (macIndex > MAC.End) {
        macLooped = true;
        macIndex = 1;
      }
    }
  });
}
