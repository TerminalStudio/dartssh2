// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:test/test.dart';

import 'package:dartssh/client.dart';
import 'package:dartssh/http.dart';
import 'package:dartssh/identity.dart';
import 'package:dartssh/pem.dart';
import 'package:dartssh/protocol.dart';
import 'package:dartssh/serializable.dart';
import 'package:dartssh/socket.dart';
import 'package:dartssh/ssh.dart';
import 'package:dartssh/websocket_io.dart';

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

  test('TestSocket', () {
    TestSocket socket = TestSocket();
    SSHClient ssh = SSHClient(
        socketInput: socket,
        print: print,
        debugPrint: print,
        tracePrint: print);
    socket.connect(Uri.parse('tcp://foobar:22'), ssh.onConnected, (_) {});
    expect(socket.sent.removeFirst(), 'SSH-2.0-dartssh_1.0\r\n');
    ssh.disconnect('done');
    expect(socket.closed, true);
  });

  test('TestHttpClient', () async {
    TestHttpClient httpClient = TestHttpClient();
    Future<bool> httpTestResult = httpTest(httpClient);
    httpClient.requests.removeFirst().completer.complete(
        HttpResponse(200, text: '<html>support@greenappers.com</html>'));
    expect(httpTestResult, completion(equals(true)));
  });

  test('cipher suite', () async {
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
        '--trace',
      ]);

      Future<void> sshMain = ssh.ssh(<String>[
        '-A',
        '-l',
        'root',
        '127.0.0.1:42022',
        '-i',
        identityFile,
        '--debug',
        '--trace',
      ], sshInput.stream, (_, String v) => sshResponse += v,
          () => sshInput.close());

      while (ssh.client.sessionChannel == null) {
        await Future.delayed(const Duration(seconds: 1));
      }
      ssh.client.sendChannelData(utf8.encode('testAgent\nexit\n'));
      await sshMain;
      await sshdMain;
      expect(sshResponse, '\$ testAgent\nexit\nsuccess\n');

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

  test('tunneled http test', () async {
    expect(httpTest(HttpClientImpl()), completion(equals(true)));
    String password = 'foobar123';

    KEX.supported =
        Key.supported = Cipher.supported = MAC.supported = (_) => true;
    Future<void> sshdMain = sshd.sshd(<String>[
      '-p 42022',
      '-h',
      'test/ssh_host_',
      '--debug',
      '--trace',
      '--forwardTcp',
      '--password',
      password
    ]);

    String sshResponse = '';
    StreamController<List<int>> sshInput = StreamController<List<int>>();
    Future<void> sshMain = ssh.ssh(<String>[
      '-l',
      'root',
      '127.0.0.1:42022',
      '--password',
      password,
      '--debug',
      '--trace',
    ], sshInput.stream, (_, String v) => sshResponse += v,
        () => sshInput.close());

    while (ssh.client.sessionChannel == null) {
      await Future.delayed(const Duration(seconds: 1));
    }
    ssh.client.setTerminalWindowSize(80, 25);
    ssh.client.exec('ls');

    bool tunneledHttpTest = await httpTest(
        HttpClientImpl(clientFactory: () => SSHTunneledBaseClient(ssh.client)),
        proto: 'http');
    expect(tunneledHttpTest, true);

    ssh.client.sendChannelData(utf8.encode('debugTest\nexit\n'));
    await sshMain;
    await sshdMain;
    expect(sshResponse, 'Password:\r\n\$ debugTest\nexit\n');
  });

  test('tunneled websocket test', () async {
    expect(websocketEchoTest(WebSocketImpl(), proto: 'ws'),
        completion(equals(true)));

    expect(websocketEchoTest(WebSocketImpl(), ignoreBadCert: true),
        completion(equals(true)));

    KEX.supported =
        Key.supported = Cipher.supported = MAC.supported = (_) => true;
    Future<void> sshdMain = sshd.sshd(<String>[
      '-p 42022',
      '-h',
      'test/ssh_host_',
      '--debug',
      '--trace',
      '--forwardTcp',
    ]);

    String sshResponse = '';
    StreamController<List<int>> sshInput = StreamController<List<int>>();
    Future<void> sshMain = ssh.ssh(<String>[
      '-l',
      'root',
      '127.0.0.1:42022',
      '--debug',
      '--trace',
    ], sshInput.stream, (_, String v) => sshResponse += v,
        () => sshInput.close());

    while (ssh.client.sessionChannel == null) {
      await Future.delayed(const Duration(seconds: 1));
    }

    bool tunneledWebsocketTest = await websocketEchoTest(
        SSHTunneledWebSocketImpl(SSHTunneledSocketImpl.fromClient(ssh.client)),
        proto: 'ws');
    expect(tunneledWebsocketTest, true);

    ssh.client.sendChannelData(utf8.encode('exit\n'));
    await sshMain;
    await sshdMain;
    expect(sshResponse, '\$ exit\n');
  });
}

Future<bool> httpTest(HttpClient httpClient, {String proto = 'https'}) async {
  var response = await httpClient.request('$proto://www.greenappers.com/');
  return response != null && response.text.contains('support@greenappers.com');
}

Future<bool> websocketEchoTest(WebSocketImpl websocket,
    {bool ignoreBadCert = false, String proto = 'wss'}) async {
  final Completer<String> connectCompleter = Completer<String>();
  websocket.connect(
      Uri.parse('$proto://echo.websocket.org'),
      () => connectCompleter.complete(null),
      (String error) => connectCompleter.complete(error),
      ignoreBadCert: ignoreBadCert);
  final String error = await connectCompleter.future;
  if (error != null) return false;

  final Completer<String> responseCompleter = Completer<String>();
  final String challenge =
      'websocketEchoTest ${base64.encode(randBytes(Random.secure(), 16))}';
  websocket.listen((Uint8List m) => responseCompleter.complete(utf8.decode(m)));
  websocket.handleError((String m) => responseCompleter.complete(m));
  websocket.handleDone((String m) => responseCompleter.complete(m));
  websocket.send(challenge);
  final String response = await responseCompleter.future;
  websocket.close();
  return response == challenge;
}
