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
  exitCode = 0;
  stdin.lineMode = false;
  stdin.echoMode = false;
  await ssh(arguments, stdin, (_, String v) => stdout.write(v), () => exit(0));
}

Future<void> ssh(List<String> arguments, Stream<List<int>> input,
    ResponseCallback response, VoidCallback done) async {
  final argParser = ArgParser()
    ..addOption('login', abbr: 'l')
    ..addOption('port', abbr: 'p')
    ..addOption('identity', abbr: 'i')
    ..addOption('tunnel')
    ..addOption('kex')
    ..addOption('key')
    ..addOption('cipher')
    ..addOption('mac')
    ..addOption('debug')
    ..addOption('trace');

  final ArgResults args = argParser.parse(arguments);

  if (args.rest.length != 1) {
    print('usage: ssh -l login hostname [args]');
    print(argParser.usage);
    exitCode = 1;
    return;
  }

  final String host = args.rest.first,
      port = args['port'],
      login = args['login'],
      identityFile = args['identity'],
      tunnel = args['tunnel'];

  if (login == null || login.isEmpty) {
    print('no login specified');
    exitCode = 1;
    return;
  }

  if (tunnel != null && tunnel.split(':').length != 2) {
    print('tunnel target should be specified host:port');
    exitCode = 2;
    return;
  }

  applyCipherSuiteOverrides(
      args['kex'], args['key'], args['cipher'], args['mac']);

  try {
    client = SSHClient(
        hostport: 'ssh://' + host + (port != null ? ':$port' : ':22'),
        login: login,
        print: print,
        debugPrint: ((args['debug'] != null) ? print : null),
        tracePrint: ((args['trace'] != null) ? print : null),
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
      if (forwardChannel != null) {
        client.sendToChannel(forwardChannel, utf8.encode(x));
      } else {
        client.sendChannelData(utf8.encode(x));
      }
    }
  } catch (error, stacktrace) {
    print('ssh: exception: $error: $stacktrace');
    exitCode = -1;
  }
}
