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

import '../example/ssh.dart' as ssh;
import '../example/sshd.dart' as sshd;

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

  test('connection', () async {
    StreamController<List<int>> sshInput = StreamController<List<int>>();
    Future<void> sshdMain = sshd.sshd(<String>[
      '-p 42022',
      '-h',
      'test/ssh_host_',
      '--debug',
      '1',
      '--trace',
      '1'
    ]);
    Future<void> sshMain = ssh.ssh(<String>[
      '-l',
      'xzebrax',
      '127.0.0.1',
      '-p',
      '42022',
      '--debug',
      '1',
      '--trace',
      '1'
    ], sshInput.stream, () => sshInput.close());

    while (ssh.client.sessionChannel == null) {
      await Future.delayed(const Duration(seconds: 1));
    }
    ssh.client.sendChannelData(utf8.encode('exit\n'));
    await sshMain;
    await sshdMain;
  });
}
