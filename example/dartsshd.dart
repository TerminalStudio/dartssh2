// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:args/args.dart';
import 'package:stack_trace/stack_trace.dart';

import 'package:dartssh2/dartssh2.dart';

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
  final SSHIdentity hostkey = loadHostKey(path: args['hostkey']);

  server = null;

  // applyCipherSuiteOverrides(
  //     args['kex'], args['key'], args['cipher'], args['mac']);

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
          socket: SSHNativeSocket()..socket = socket,
          hostport: SSH.parseUri(hostport),
          print: print,
          debugPrint: debug ? print : null,
          tracePrint: args['trace'] ? print : null,
          response: (Uint8List v) {
            input.add(utf8.decode(v));
            server!.sendChannelData(v);
          },
          userAuthRequest: (msg) {
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
            // server!.writeCipher(MSG_DEBUG());
            // server!.writeCipher(MSG_IGNORE());
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

Future chainWork(Future? chain, Future Function() x) =>
    chain == null ? x() : chain.then((_) async => await x());

SSHIdentity loadHostKey({String Function()? getPassword, String? path}) {
  SSHIdentity hostkey = SSHIdentity();
  path ??= '/etc/ssh/ssh_host_';
  try {
    SSHIdentity.fromPem(File('${path}ecdsa_key').readAsStringSync(),
        identity: hostkey, getPassword: getPassword);
  } catch (error) {
    print('open ${path}ecdsa_key failed');
  }
  try {
    SSHIdentity.fromPem(File('${path}ed25519_key').readAsStringSync(),
        identity: hostkey, getPassword: getPassword);
  } catch (error) {
    print('open ${path}ed25519_key failed');
  }
  try {
    SSHIdentity.fromPem(File('${path}rsa_key').readAsStringSync(),
        identity: hostkey, getPassword: getPassword);
  } catch (error) {
    print('open ${path}rsa_key failed');
  }
  return hostkey;
}

Future<String?> forwardTcpChannel(
  SSHChannel channel,
  String? sourceHost,
  int? sourcePort,
  String? targetHost,
  int? targetPort,
) async {
  SSHNativeSocket tunneledSocket = SSHNativeSocket();
  final connectCompleter = Completer<String?>();
  print('dartsshd: Forwarding connection to $targetHost:$targetPort');
  tunneledSocket.connect(
    Uri.parse('tcp://$targetHost:$targetPort'),
    () => connectCompleter.complete(null),
    (String? error) => connectCompleter.complete('$error'),
  );
  final connectError = await connectCompleter.future;
  if (connectError != null) return connectError;

  void closeTunneledSocket(String? error) {
    final reason = error == null ? '' : ': $error';
    print("dartsshd: Closing forwarded connection to $targetHost:$targetPort" +
        reason);
    tunneledSocket.close();
    server!.closeChannel(channel);
  }

  tunneledSocket.listen((Uint8List m) => server!.sendToChannel(channel, m));
  tunneledSocket.handleError(closeTunneledSocket);
  tunneledSocket.handleDone(closeTunneledSocket);

  channel.cb = (Uint8List? m) => tunneledSocket.sendBinary(m!);
  channel.error = closeTunneledSocket;
  channel.closed = () => closeTunneledSocket('remote closed');
  return null;
}

Future testAgentForwarding() async {
//   SSHChannel? agentChannel;
//   Uint8List key, challenge;
//   final openCompleter = Completer<String?>();
//   final doneCompleter = Completer<String?>();
//   agentChannel = server!.openAgentChannel(
//     (Uint8List? read) => SSHAgentForwarding.dispatchAgentRead(
//       agentChannel!,
//       read!,
//       (_, agentPacketS) {
//         int agentPacketId = agentPacketS.getUint8();
//         switch (agentPacketId) {
//           case AGENT_IDENTITIES_ANSWER.ID:
//             AGENT_IDENTITIES_ANSWER msg = AGENT_IDENTITIES_ANSWER()
//               ..deserialize(agentPacketS);
//             assert(msg.keys.isNotEmpty);
//             key = msg.keys.first.key;
//             challenge = randBytes(Random.secure(), 16);
//             server!.sendToChannel(
//                 agentChannel!, AGENTC_SIGN_REQUEST(key, challenge).toRaw());
//             break;

//           case AGENT_SIGN_RESPONSE.ID:
//             AGENT_SIGN_RESPONSE msg = AGENT_SIGN_RESPONSE()
//               ..deserialize(agentPacketS);
//             assert(msg.sig!.isNotEmpty);
//             doneCompleter.complete(null);
//             break;

//           default:
//             break;
//         }
//       },
//     ),
//     connected: () => openCompleter.complete(null),
//     error: (String? error) => openCompleter.complete('$error'),
//   );
//   final openError = await openCompleter.future;
//   if (openError != null) {
//     server!.sendChannelData(utf8.encode('error: $openError\n') as Uint8List);
//     return;
//   }
//   server!.sendToChannel(agentChannel!, AGENTC_REQUEST_IDENTITIES().toRaw());
//   final doneError = await doneCompleter.future;
//   if (doneError == null) {
  server!.sendChannelData(utf8.encode('success\n') as Uint8List);
//   } else {
//     server!.sendChannelData(utf8.encode('error: $doneError\n') as Uint8List);
//   }
}
