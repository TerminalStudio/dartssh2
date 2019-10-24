// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:io';

import 'package:args/args.dart';

import 'package:dartssh/client.dart';

void main(List<String> arguments) async {
  exitCode = 0;

  final argParser = ArgParser()
    ..addOption('login', abbr: 'l')
    ..addOption('port', abbr: 'p');
  final ArgResults argResults = argParser.parse(arguments);

  if (argResults.rest.length != 1) {
    print('ssh: <host> [args]');
    print(argParser.usage);
    exitCode = 1;
    return;
  }

  final String host = argResults.rest.first;
  final String port = argResults['port'];

  try {
    final SSHClient ssh = SSHClient(
        hostport: 'ssh://' + host + (port != null ? ':$port' : ''),
        debugPrint: print,
        tracePrint: print);
  } catch (error, stacktrace) {
    print('ssh: exception: $error: $stacktrace');
    exitCode = -1;
  }
}
