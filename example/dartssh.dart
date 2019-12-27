// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:args/args.dart';

import 'package:dartssh/client.dart';
import 'package:dartssh/identity.dart';
import 'package:dartssh/pem.dart';
import 'package:dartssh/ssh.dart';
import 'package:dartssh/transport.dart';

Identity identity;
SSHClient client;
Channel forwardChannel;

void main(List<String> arguments) async {
  stdin.lineMode = false;
  stdin.echoMode = false;
  ProcessSignal.sigint.watch().listen((_) {
    if (client != null) send(Uint8List.fromList(<int>[3]));
  });
  ProcessSignal.sigwinch.watch().listen((_) {
    if (client != null) {
      client.setTerminalWindowSize(
          stdout.terminalColumns, stdout.terminalLines);
    }
  });
  exitCode = await ssh(
      arguments, stdin, (_, String v) => stdout.write(v), () => exit(0),
      termWidth: stdout.terminalColumns, termHeight: stdout.terminalLines);
}

void send(Uint8List x) {
  if (forwardChannel != null) {
    client.sendToChannel(forwardChannel, x);
  } else {
    client.sendChannelData(x);
  }
}

Future<int> ssh(List<String> arguments, Stream<List<int>> input,
    ResponseCallback response, VoidCallback done,
    {int termWidth = 80, int termHeight = 25}) async {
  final argParser = ArgParser()
    ..addOption('login', abbr: 'l')
    ..addOption('identity', abbr: 'i')
    ..addOption('password')
    ..addOption('tunnel')
    ..addOption('kex')
    ..addOption('key')
    ..addOption('cipher')
    ..addOption('mac')
    ..addFlag('debug')
    ..addFlag('trace')
    ..addFlag('agentForwarding', abbr: 'A');

  final ArgResults args = argParser.parse(arguments);

  identity = null;
  client = null;
  forwardChannel = null;

  if (args.rest.length != 1) {
    print('usage: ssh -l login url [args]');
    print(argParser.usage);
    return 1;
  }

  final String host = args.rest.first,
      login = args['login'],
      identityFile = args['identity'],
      tunnel = args['tunnel'];

  if (login == null || login.isEmpty) {
    print('no login specified');
    return 1;
  }

  if (tunnel != null && tunnel.split(':').length != 2) {
    print('tunnel target should be specified host:port');
    return 2;
  }

  applyCipherSuiteOverrides(
      args['kex'], args['key'], args['cipher'], args['mac']);

  try {
    client = SSHClient(
        hostport: parseUri(host),
        login: login,
        print: print,
        termWidth: termWidth,
        termHeight: termHeight,
        termvar: Platform.environment['TERM'] ?? 'xterm',
        agentForwarding: args['agentForwarding'],
        debugPrint: args['debug'] ? print : null,
        tracePrint: args['trace'] ? print : null,
        getPassword: ((args['password'] != null)
            ? () => utf8.encode(args['password'])
            : null),
        response: response,
        loadIdentity: () {
          if (identity == null && identityFile != null) {
            identity = parsePem(File(identityFile).readAsStringSync());
          }
          return identity;
        },
        disconnected: done,
        startShell: tunnel == null,
        success: tunnel == null
            ? null
            : () {
                List<String> tunnelTarget = tunnel.split(':');
                forwardChannel = client.openTcpChannel(
                    '127.0.0.1',
                    1234,
                    tunnelTarget[0],
                    int.parse(tunnelTarget[1]),
                    (_, Uint8List m) => response(client, utf8.decode(m)));
              });

    await for (String x in input.transform(utf8.decoder)) {
      send(utf8.encode(x));
    }
  } catch (error, stacktrace) {
    print('ssh: exception: $error: $stacktrace');
    return -1;
  }

  return 0;
}
