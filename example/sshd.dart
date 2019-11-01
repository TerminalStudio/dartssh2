// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:io';

import 'package:args/args.dart';
import 'package:stack_trace/stack_trace.dart';

import 'package:dartssh/identity.dart';
import 'package:dartssh/pem.dart';
import 'package:dartssh/socket_io.dart';
import 'package:dartssh/server.dart';
import 'package:dartssh/transport.dart';

void main(List<String> arguments) async {
  exitCode = 0;

  final argParser = ArgParser()
    ..addOption('port', abbr: 'p')
    ..addOption('config', abbr: 'f')
    ..addOption('hostkey', abbr: 'h')
    ..addOption('debug')
    ..addOption('trace');

  final ArgResults args = argParser.parse(arguments);
  final int port = int.parse(args['port'] ?? '22');
  final String config = args['config'];
  Identity hostkey = loadHostKey(path: args['hostkey']);

  try {
    await Chain.capture(() async {
      ServerSocket listener = await ServerSocket.bind('0.0.0.0', port);
      await for (Socket socket in listener) {
        String hostport = '${socket.remoteAddress.host}:${socket.remotePort}';
        print('accepted $hostport');
        final SSHServer server = SSHServer(hostkey,
            socket: SocketImpl()..socket = socket,
            hostport: hostport,
            print: print,
            debugPrint: ((args['debug'] != null) ? print : null),
            tracePrint: ((args['trace'] != null) ? print : null),
            response: (String v) => stdout.write(v),
            disconnected: () {
              print('disconnected');
            });
      }
    });
  } catch (error, stacktrace) {
    print('sshd: exception: $error: $stacktrace');
    exitCode = -1;
  }
}

Identity loadHostKey({StringFunction getPassword, String path}) {
  Identity hostkey = Identity();
  path ??= '/etc/ssh/ssh_host_';
  try {
    parsePem(File('${path}ecdsa_key').readAsStringSync(),
        identity: hostkey, getPassword: getPassword);
  } catch (error) {}
  try {
    parsePem(File('${path}ed25519_key').readAsStringSync(),
        identity: hostkey, getPassword: getPassword);
  } catch (error) {}
  try {
    parsePem(File('${path}rsa_key').readAsStringSync(),
        identity: hostkey, getPassword: getPassword);
  } catch (error) {}
  return hostkey;
}
