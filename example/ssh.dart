// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:io';

import 'package:args/args.dart';

import 'package:dartssh/client.dart';

void main(List<String> arguments) async {
  exitCode = 0;

  final argParser = ArgParser()
    ..addOption('login', abbr: 'l')
    ..addOption('port', abbr: 'p')
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

  if (login == null || login.isEmpty) {
    print('no login specified');
    exitCode = 1;
    return;
  }

  try {
    final SSHClient ssh = SSHClient(
        hostport: 'ssh://' + host + (port != null ? ':$port' : ':22'),
        user: login,
        print: print,
        debugPrint: ((args['debug'] ?? false) ? print : null),
        tracePrint: ((args['trace'] ?? false) ? print : null),
        response: (String v) => stdout.write(v),
        );

    stdin.lineMode = false;
    stdin.echoMode = false;
    await for (String input in stdin.transform(utf8.decoder)) {
      ssh.sendChannelData(utf8.encode(input));
    }

  } catch (error, stacktrace) {
    print('ssh: exception: $error: $stacktrace');
    exitCode = -1;
  }
}
