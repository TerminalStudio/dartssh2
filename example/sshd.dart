// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:io';

import 'package:args/args.dart';

import 'package:dartssh/client.dart';
import 'package:dartssh/identity.dart';
import 'package:dartssh/pem.dart';
import 'package:dartssh/socket_io.dart';

void main(List<String> arguments) async {
  exitCode = 0;

  final argParser = ArgParser()
    ..addOption('port', abbr: 'p')
    ..addOption('config', abbr: 'f')
    ..addOption('hostkey', abbr: 'h')
    ..addOption('debug')
    ..addOption('trace');

  final ArgResults args = argParser.parse(arguments);

  if (args.rest.length != 1) {
    print('usage: sshd [args]');
    print(argParser.usage);
    exitCode = 1;
    return;
  }

  final int port = int.parse(args['port'] ?? '22');
  final String config = args['config'];
  Identity hostkey = loadHostKey(path: args['hostkey']);

  try {
    ServerSocket listener = await ServerSocket.bind('0.0.0.0', port);
    await for (Socket socket in listener) {
      final SSHClient client = SSHClient(
          socket: SocketImpl()..socket = socket,
          print: print,
          debugPrint: ((args['debug'] != null) ? print : null),
          tracePrint: ((args['trace'] != null) ? print : null),
          response: (String v) => stdout.write(v),
          disconnected: () { print('disconnected'); });
      client.onConnected(client.socket);
    }

  } catch (error, stacktrace) {
    print('sshd: exception: $error: $stacktrace');
    exitCode = -1;
  }
}

Identity loadHostKey({StringFunction getPassword, String path}) {
  Identity hostkey = Identity();
  path ??= '/etc/ssh/ssh_host_';
  parsePem(File('${path}ecdsa_key').readAsStringSync(),
      identity: hostkey, getPassword: getPassword);
  parsePem(File('${path}ed25519_key').readAsStringSync(),
      identity: hostkey, getPassword: getPassword);
  parsePem(File('${path}rsa_key').readAsStringSync(),
      identity: hostkey, getPassword: getPassword);
  return hostkey;
}
