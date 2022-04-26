import 'dart:io';

import 'package:dartssh2/dartssh2.dart';

import 'ssh_opts.dart';
import 'utils.dart';

Future<SSHClient> startClientWithOpts(SSHConnectOpts opts) async {
  return SSHClient(
    await SSHSocket.connect(opts.target.host, opts.target.port),
    username: opts.target.user ?? currentUsername ?? 'root',
    printDebug: opts.verbose ? print : null,
    printTrace: opts.verbose ? print : null,
    identities: findIdentities(),
    onUserauthBanner: (String banner) {
      print(banner);
    },
    onPasswordRequest: () {
      return readline('Password: ', echo: false);
    },
    onUserInfoRequest: (request) {
      if (request.name.isNotEmpty) {
        print(request.name);
      }

      if (request.instruction.isNotEmpty) {
        print(request.instruction);
      }

      final responses = <String>[];
      for (var prompt in request.prompts) {
        final response = readline(prompt.promptText, echo: prompt.echo);
        responses.add(response);
      }

      return responses;
    },
  );
}

String? get currentUsername {
  return Platform.environment['USERNAME'];
}

List<SSHKeyPair> findIdentity(String filename) {
  final file = File(filename);
  return file.existsSync() ? SSHKeyPair.fromPem(file.readAsStringSync()) : [];
}

List<SSHKeyPair> findIdentities() {
  final files = <String>[
    '$homeDir/.ssh/id_rsa',
    '$homeDir/.ssh/id_ed25519',
    '$homeDir/.ssh/id_ecdsa',
  ];

  return files
      .map((filename) => findIdentity(filename))
      .expand((x) => x)
      .toList();
}
