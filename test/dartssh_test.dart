// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dartssh2/src/transport.dart';
import 'package:test/test.dart';

import 'package:dartssh2/src/client.dart';
import 'package:dartssh2/src/http.dart';
import 'package:dartssh2/src/identity.dart';
import 'package:dartssh2/src/pem.dart';
import 'package:dartssh2/src/protocol.dart';
import 'package:dartssh2/src/serializable.dart';
import 'package:dartssh2/src/socket.dart';
import 'package:dartssh2/src/ssh.dart';
import 'package:dartssh2/src/websocket_io.dart';

import '../example/dartssh.dart' as ssh;
import '../example/dartsshd.dart' as sshd;

void main() {
  /// https://www.ietf.org/rfc/rfc4251.txt
  test('mpint', () {
    Uint8List buffer = Uint8List(4096);
    SerializableInput input = SerializableInput(buffer, endian: Endian.big);
    SerializableOutput output = SerializableOutput(buffer, endian: Endian.big);

    BigInt x = BigInt.from(0);
    print(x.bitLength);
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
    SSHIdentity rsa1 = parsePem(File('test/id_rsa').readAsStringSync());
    SSHIdentity rsa2 = parsePem(File('test/id_rsa.openssh').readAsStringSync());
    expect(rsa1.rsaPublic!.exponent, rsa2.rsaPublic!.exponent);
  });

  test('TestSocket', () {
    TestSocket socket = TestSocket();
    SSHClient ssh = SSHClient(
      username: 'whoever',
      socketInput: socket,
      print: print,
      debugPrint: print,
      tracePrint: print,
    );
    socket.connect(Uri.parse('tcp://foobar:22'), ssh.onConnected, (_) {});
    expect(socket.sent.removeFirst(), 'SSH-2.0-dartssh_1.0\r\n');
    ssh.disconnect('done');
    expect(socket.closed, true);
  });

  test('TestKeepAlive', () async {
    TestSocket socket = TestSocket();
    SSHClient ssh = SSHClient(
        username: 'whoever',
        socketInput: socket,
        print: print,
        debugPrint: print,
        tracePrint: print,
        keepaliveConfig: KeepaliveConfig(
            keepaliveCountMax: 3,
            keepaliveInterval: Duration(milliseconds: 10)));
    socket.connect(Uri.parse('tcp://foobar:22'), ssh.onConnected, (_) {});

    await Future.delayed(Duration(milliseconds: 200));
    expect(ssh.pingCount < 10, true);

    ssh.disconnect('done');
    expect(socket.closed, true);
  });

  test('TestHttpClient', () async {
    TestHttpClient httpClient = TestHttpClient();
    Future<bool> httpTestResult = httpTest(httpClient);
    httpClient.requests
        .removeFirst()
        .completer
        .complete(HttpResponse(426, text: 'Expected Upgrade'));
    expect(await httpTestResult, isTrue);
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
      List<int> sshResponse = [];
      String identityFile;

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

      Future<void> sshMain = ssh.ssh(
        <String>[
          '-A',
          '-l',
          'root',
          '127.0.0.1:42022',
          '-i',
          identityFile,
          '--debug',
          '--trace',
        ],
        sshInput.stream,
        (Uint8List v) => sshResponse += v,
        () => sshInput.close(),
      );

      while (ssh.client!.sessionChannel == null) {
        await Future.delayed(const Duration(seconds: 1));
      }
      ssh.client!
          .sendChannelData(utf8.encode('testAgent\nexit\n') as Uint8List);
      await sshMain;
      await sshdMain;
      expect(utf8.decode(sshResponse), '\$ testAgent\nexit\nsuccess\n');

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
    expect(await httpTest(HttpClientImpl()), isTrue);
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

    var sshResponse = <int>[];
    final sshInput = StreamController<List<int>>();
    Future<void> sshMain = ssh.ssh(
      <String>[
        '-l',
        'root',
        '127.0.0.1:42022',
        '--password',
        password,
        '--debug',
        '--trace',
      ],
      sshInput.stream,
      (Uint8List v) => sshResponse += v,
      () => sshInput.close(),
    );

    while (ssh.client!.sessionChannel == null) {
      await Future.delayed(const Duration(seconds: 1));
    }

    ssh.client!.setTerminalWindowSize(80, 25);
    ssh.client!.exec('ls');

    bool tunneledHttpTest = await httpTest(
      HttpClientImpl(clientFactory: () => SSHTunneledBaseClient(ssh.client!)),
      proto: 'http', // SSHTunneledBaseClient does not support https
    );
    expect(tunneledHttpTest, true);

    ssh.client!.sendChannelData(utf8.encode('debugTest\nexit\n') as Uint8List);
    await sshMain;
    await sshdMain;
    expect(utf8.decode(sshResponse), '\$ debugTest\nexit\n');
  });

  test('tunneled websocket test', () async {
    expect(
      await websocketEchoTest(WebSocketImpl(), proto: 'ws'),
      isTrue,
    );

    expect(
      await websocketEchoTest(WebSocketImpl(), ignoreBadCert: true),
      isTrue,
    );

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

    List<int> sshResponse = [];
    StreamController<List<int>> sshInput = StreamController<List<int>>();
    Future<void> sshMain = ssh.ssh(<String>[
      '-l',
      'root',
      '127.0.0.1:42022',
      '--debug',
      '--trace',
    ], sshInput.stream, (Uint8List v) => sshResponse += v,
        () => sshInput.close());

    while (ssh.client!.sessionChannel == null) {
      await Future.delayed(const Duration(seconds: 1));
    }

    bool tunneledWebsocketTest = await websocketEchoTest(
        SSHTunneledWebSocketImpl(SSHTunneledSocketImpl.fromClient(ssh.client!)),
        proto: 'ws');
    expect(tunneledWebsocketTest, true);

    ssh.client!.sendChannelData(utf8.encode('exit\n') as Uint8List);
    await sshMain;
    await sshdMain;
    expect(utf8.decode(sshResponse), '\$ exit\n');
  });
}

Future<bool> httpTest(HttpClient httpClient, {String proto = 'https'}) async {
  var response = await httpClient.request('$proto://echo.terminal.studio/');
  return response.text!.contains('Expected Upgrade');
}

Future<bool> websocketEchoTest(
  WebSocketImpl websocket, {
  bool ignoreBadCert = false,
  String proto = 'wss',
}) async {
  final connectCompleter = Completer<String?>();

  websocket.connect(
    Uri.parse('$proto://echo.terminal.studio'),
    () => connectCompleter.complete(null),
    (String? error) => connectCompleter.complete(error),
    ignoreBadCert: ignoreBadCert,
  );

  final error = await connectCompleter.future;
  if (error != null) return false;

  final responseCompleter = Completer<String>();
  final challenge =
      'websocketEchoTest ${base64.encode(randBytes(Random.secure(), 16))}';
  websocket.listen((Uint8List m) => responseCompleter.complete(utf8.decode(m)));
  websocket.handleError((String? m) => responseCompleter.complete(m));
  websocket.handleDone((String? m) => responseCompleter.complete(m));
  websocket.send(challenge);

  final response = await responseCompleter.future;
  websocket.close();
  return response == challenge;
}
