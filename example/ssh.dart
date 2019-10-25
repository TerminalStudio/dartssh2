// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:args/args.dart';

import 'package:dartssh/client.dart';
import 'package:dartssh/serializable.dart';

void main(List<String> arguments) async {
  exitCode = 0;

  final argParser = ArgParser()
    ..addOption('login', abbr: 'l')
    ..addOption('port', abbr: 'p');
  final ArgResults argResults = argParser.parse(arguments);

  if (argResults.rest.length != 1) {
    print('usage: ssh -l login hostname [args]');
    print(argParser.usage);
    exitCode = 1;
    return;
  }

  final String host = argResults.rest.first;
  final String port = argResults['port'];
  final String login = argResults['login'];

  if (login == null || login.isEmpty) {
    print('no login specified');
    exitCode = 1;
    return;
  }

  try {
    stdin.lineMode = false;
    stdin.echoMode = false;
    Uint8List loadingPassword;

    final SSHClient ssh = SSHClient(
        hostport: 'ssh://' + host + (port != null ? ':$port' : ':22'),
        response: (String v) => stdout.write(v),
        user: login,
        print: print,
        debugPrint: print,
        tracePrint: print,
        getPassword: () {
          loadingPassword = Uint8List(0);
          Uint8List ret;
          return ret;
        });

    await for (String input in stdin.transform(utf8.decoder)) {
      for (int i = 0; i < input.length; i++) {
        String char = input[i];

        if (loadingPassword != null) {
          if (char == '\n') {
            ssh.pw = loadingPassword;
            ssh.sendPassword();
            loadingPassword = null;
          } else {
            loadingPassword =
                appendUint8List(loadingPassword, utf8.encode(char));
          }
        }
      }
    }
  } catch (error, stacktrace) {
    print('ssh: exception: $error: $stacktrace');
    exitCode = -1;
  }
}
