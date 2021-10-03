// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:args/args.dart';
import 'package:stack_trace/stack_trace.dart';

import 'package:dartssh2/agent.dart';
import 'package:dartssh2/identity.dart';
import 'package:dartssh2/pem.dart';
import 'package:dartssh2/protocol.dart';
import 'package:dartssh2/socket_io.dart';
import 'package:dartssh2/server.dart';
import 'package:dartssh2/ssh.dart';
import 'package:dartssh2/transport.dart';

SSHServer? server;

void main(List<String> arguments) async {
  exitCode = 0;
  await sshd(arguments);
}

Future<void> sshd(List<String> arguments) async {
  final argParser = ArgParser()
    ..addOption('port', abbr: 'p')
    ..addOption('config', abbr: 'f')
    ..addOption('hostkey', abbr: 'h')
    ..addOption('password')
    ..addOption('kex')
    ..addOption('key')
    ..addOption('cipher')
    ..addOption('mac')
    ..addFlag('debug')
    ..addFlag('trace')
    ..addFlag('forwardTcp');

  final ArgResults args = argParser.parse(arguments);
  final int port = int.parse(args['port'] ?? '22');
  final bool debug = args['debug'], forwardTcp = args['forwardTcp'];
  final Identity hostkey = loadHostKey(path: args['hostkey']);

  server = null;

  applyCipherSuiteOverrides(
      args['kex'], args['key'], args['cipher'], args['mac']);

  if (forwardTcp) {
    print(
        'WARNING: Forwarding TCP connections is in effect running an open proxy.');
  }

  try {
    await Chain.capture(() async {
      final listener = await ServerSocket.bind('0.0.0.0', port, shared: true);

      await for (Socket socket in listener) {
        final String hostport =
            '${socket.remoteAddress.host}:${socket.remotePort}';
        print('accepted $hostport');
        StreamController<String> input = StreamController<String>();
        bool done = false;
        Future? pending;

        server = SSHServer(
          hostkey,
          socket: SocketImpl()..socket = socket,
          hostport: parseUri(hostport),
          print: print,
          debugPrint: debug ? print : null,
          tracePrint: args['trace'] ? print : null,
          response: (SSHTransport server, Uint8List v) {
            input.add(utf8.decode(v));
            server.sendChannelData(v);
          },
          userAuthRequest: (MSG_USERAUTH_REQUEST msg) {
            final requirePassword = args['password'];
            if ((requirePassword ?? '').isEmpty) {
              /// Graciously accept all authorization requests.
              return true;
            } else {
              return (msg.methodName ?? '') == 'password' &&
                  utf8.decode(msg.secret ?? []) == requirePassword;
            }
          },
          sessionChannelRequest: (SSHServer server, String? req) {
            if (req == 'shell') {
              server.sendChannelData(utf8.encode('\$ ') as Uint8List);
              return true;
            } else if (req == 'pty-req') {
              return true;
            } else {
              return false;
            }
          },
          disconnected: () {
            if (debug) {
              print('dartsshd: $hostport: disconnected');
              listener.close();
            }
          },
          directTcpRequest: forwardTcp ? forwardTcpChannel : null,
        );

        input.stream.transform(LineSplitter()).listen((String line) {
          if (done) return;
          if (line == 'exit') {
            done = true;
            pending = chainWork(pending,
                () async => server!.closeChannel(server!.sessionChannel!));
          } else if (line == 'testAgent') {
            pending = chainWork(pending, () => testAgentForwarding());
          } else if (line == 'testDebug') {
            server!.writeCipher(MSG_DEBUG());
            server!.writeCipher(MSG_IGNORE());
            server!.sendChannelData(utf8.encode('success\n') as Uint8List);
          }
        });
      }
    });
  } catch (error, stacktrace) {
    print('sshd: exception: $error: $stacktrace');
    exitCode = -1;
  }
}

Future chainWork(Future? chain, FutureFunction x) =>
    chain == null ? x() : chain.then((_) async => await x());

Identity loadHostKey({StringFunction? getPassword, String? path}) {
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

Future<String?> forwardTcpChannel(
  Channel channel,
  String? sourceHost,
  int? sourcePort,
  String? targetHost,
  int? targetPort,
) async {
  SocketImpl tunneledSocket = SocketImpl();
  final connectCompleter = Completer<String?>();
  print('dartsshd: Forwarding connection to $targetHost:$targetPort');
  tunneledSocket.connect(
    Uri.parse('tcp://$targetHost:$targetPort'),
    () => connectCompleter.complete(null),
    (String? error) => connectCompleter.complete('$error'),
  );
  final connectError = await connectCompleter.future;
  if (connectError != null) return connectError;

  StringCallback closeTunneledSocket = (String? error) {
    final reason = error == null ? '' : ': $error';
    print("dartsshd: Closing forwarded connection to $targetHost:$targetPort" +
        reason);
    tunneledSocket.close();
    server!.closeChannel(channel);
  };
  tunneledSocket.listen((Uint8List m) => server!.sendToChannel(channel, m));
  tunneledSocket.handleError(closeTunneledSocket);
  tunneledSocket.handleDone(closeTunneledSocket);

  channel.cb = (_, Uint8List? m) => tunneledSocket.sendRaw(m!);
  channel.error = closeTunneledSocket;
  channel.closed = () => closeTunneledSocket('remote closed');
  return null;
}

Future testAgentForwarding() async {
  Channel? agentChannel;
  Uint8List key, challenge;
  final openCompleter = Completer<String?>();
  final doneCompleter = Completer<String?>();
  agentChannel = server!.openAgentChannel(
    (_, Uint8List? read) => SSHAgentForwarding.dispatchAgentRead(
      agentChannel!,
      read!,
      (_, agentPacketS) {
        int agentPacketId = agentPacketS.getUint8();
        switch (agentPacketId) {
          case AGENT_IDENTITIES_ANSWER.ID:
            AGENT_IDENTITIES_ANSWER msg = AGENT_IDENTITIES_ANSWER()
              ..deserialize(agentPacketS);
            assert(msg.keys.isNotEmpty);
            key = msg.keys.first.key;
            challenge = randBytes(Random.secure(), 16);
            server!.sendToChannel(
                agentChannel!, AGENTC_SIGN_REQUEST(key, challenge).toRaw());
            break;

          case AGENT_SIGN_RESPONSE.ID:
            AGENT_SIGN_RESPONSE msg = AGENT_SIGN_RESPONSE()
              ..deserialize(agentPacketS);
            assert(msg.sig!.isNotEmpty);
            doneCompleter.complete(null);
            break;

          default:
            break;
        }
      },
    ),
    connected: () => openCompleter.complete(null),
    error: (String? error) => openCompleter.complete('$error'),
  );
  final openError = await openCompleter.future;
  if (openError != null) {
    server!.sendChannelData(utf8.encode('error: $openError\n') as Uint8List);
    return;
  }
  server!.sendToChannel(agentChannel!, AGENTC_REQUEST_IDENTITIES().toRaw());
  final doneError = await doneCompleter.future;
  if (doneError == null) {
    server!.sendChannelData(utf8.encode('success\n') as Uint8List);
  } else {
    server!.sendChannelData(utf8.encode('error: $doneError\n') as Uint8List);
  }
}
