// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:args/args.dart';
import 'package:stack_trace/stack_trace.dart';

import 'package:dartssh/identity.dart';
import 'package:dartssh/pem.dart';
import 'package:dartssh/protocol.dart';
import 'package:dartssh/socket_io.dart';
import 'package:dartssh/server.dart';
import 'package:dartssh/ssh.dart';
import 'package:dartssh/transport.dart';

SSHServer server;

void main(List<String> arguments) async {
  exitCode = 0;
  await sshd(arguments);
}

Future<void> sshd(List<String> arguments) async {
  final argParser = ArgParser()
    ..addOption('port', abbr: 'p')
    ..addOption('config', abbr: 'f')
    ..addOption('hostkey', abbr: 'h')
    ..addOption('kex')
    ..addOption('key')
    ..addOption('cipher')
    ..addOption('mac')
    ..addFlag('debug')
    ..addFlag('trace')
    ..addFlag('forwardTcp');

  final ArgResults args = argParser.parse(arguments);
  final int port = int.parse(args['port'] ?? '22');
  final String config = args['config'];
  final bool debug = args['debug'], forwardTcp = args['forwardTcp'];
  final Identity hostkey = loadHostKey(path: args['hostkey']);

  applyCipherSuiteOverrides(
      args['kex'], args['key'], args['cipher'], args['mac']);

  if (forwardTcp) {
    print(
        'WARNING: Forwarding TCP connections is in effect running an open proxy.');
  }

  try {
    await Chain.capture(() async {
      final ServerSocket listener = await ServerSocket.bind('0.0.0.0', port);

      await for (Socket socket in listener) {
        final String hostport =
            '${socket.remoteAddress.host}:${socket.remotePort}';
        print('accepted $hostport');
        StreamController<String> input = StreamController<String>();

        server = SSHServer(
          hostkey,
          socket: SocketImpl()..socket = socket,
          hostport: parseUri(hostport),
          print: print,
          debugPrint: debug ? print : null,
          tracePrint: args['trace'] ? print : null,
          response: (SSHTransport server, String v) {
            input.add(v);
            server.sendChannelData(utf8.encode(v));
          },

          /// Graciously accept all authorization requests.
          userAuthRequest: (MSG_USERAUTH_REQUEST msg) => true,
          sessionChannelRequest: (SSHServer server, String req) {
            if (req == 'shell') {
              server.sendChannelData(utf8.encode('\$ '));
              return true;
            } else if (req == 'pty-req') {
              return true;
            } else {
              return false;
            }
          },
          disconnected: () {
            if (debug) {
              print('disconnected');
              listener.close();
            }
          },
          directTcpRequest: forwardTcp ? forwardTcpChannel : null,
        );
        input.stream.transform(LineSplitter()).listen((String line) {
          if (line == 'exit') server.closeChannel(server.sessionChannel);
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
  } catch (error) {
    print('open ${path}ecdsa_key failed');
  }
  try {
    parsePem(File('${path}ed25519_key').readAsStringSync(),
        identity: hostkey, getPassword: getPassword);
  } catch (error) {
    print('open ${path}ed25519_key failed');
  }
  try {
    parsePem(File('${path}rsa_key').readAsStringSync(),
        identity: hostkey, getPassword: getPassword);
  } catch (error) {
    print('open ${path}rsa_key failed');
  }
  return hostkey;
}

Future<String> forwardTcpChannel(Channel channel, String sourceHost,
    int sourcePort, String targetHost, int targetPort) async {
  SocketImpl tunneledSocket = SocketImpl();
  Completer<String> connectCompleter = Completer<String>();
  tunneledSocket.connect(
      Uri.parse('tcp://$targetHost:$targetPort'),
      () => connectCompleter.complete(null),
      (String error) => connectCompleter.complete('$error'));
  String connectError = await connectCompleter.future;
  if (connectError != null) return connectError;

  StringCallback closeTunneledSocket = (String error) {
    tunneledSocket.close();
    server.closeChannel(channel);
  };
  tunneledSocket.listen((Uint8List m) => server.sendToChannel(channel, m));
  tunneledSocket.handleError(closeTunneledSocket);
  tunneledSocket.handleDone(closeTunneledSocket);

  channel.cb = (_, Uint8List m) => tunneledSocket.sendRaw(m);
  channel.error = closeTunneledSocket;
  return null;
}
