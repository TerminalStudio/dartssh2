// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:io';

import 'package:args/args.dart';

import 'package:dartssh/client.dart';
import 'package:dartssh/identity.dart';
import 'package:dartssh/pem.dart';
import 'package:dartssh/transport.dart';

Identity identity;
SSHClient client;

void main(List<String> arguments) async {
  exitCode = 0;
  stdin.lineMode = false;
  stdin.echoMode = false;
  await ssh(arguments, stdin, () => exit(0));
}

Future<void> ssh(
    List<String> arguments, Stream<List<int>> input, VoidCallback done) async {
  final argParser = ArgParser()
    ..addOption('login', abbr: 'l')
    ..addOption('port', abbr: 'p')
    ..addOption('identity', abbr: 'i')
    ..addOption('debug')
    ..addOption('trace');

  final ArgResults args = argParser.parse(arguments);

  if (args.rest.length != 1) {
    print('usage: ssh -l login hostname [args]');
    print(argParser.usage);
    exitCode = 1;
    return;
  }

  final String host = args.rest.first;
  final String port = args['port'];
  final String login = args['login'];
  final String identityFile = args['identity'];

  if (login == null || login.isEmpty) {
    print('no login specified');
    exitCode = 1;
    return;
  }

  try {
    client = SSHClient(
        hostport: 'ssh://' + host + (port != null ? ':$port' : ':22'),
        login: login,
        print: print,
        debugPrint: ((args['debug'] != null) ? print : null),
        tracePrint: ((args['trace'] != null) ? print : null),
        response: (_, String v) => stdout.write(v),
        loadIdentity: () {
          if (identity == null && identityFile != null) {
            identity = parsePem(File(identityFile).readAsStringSync());
          }
          return identity;
        },
        disconnected: done);

    await for (String x in input.transform(utf8.decoder)) {
      client.sendChannelData(utf8.encode(x));
    }
  } catch (error, stacktrace) {
    print('ssh: exception: $error: $stacktrace');
    exitCode = -1;
  }
}
