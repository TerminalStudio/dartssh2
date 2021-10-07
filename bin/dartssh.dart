import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:dart_console/dart_console.dart';
import 'package:dartssh2/dartssh2.dart';

import 'src/ssh_args.dart';
import 'src/utils.dart';

void main(List<String> arguments) {
  SSHCommand.start(arguments);
}

class SSHCommand {
  final console = Console();

  final SSHCommandArgs args;

  SSHCommand.start(List<String> arguments) : args = mustParseArgs(arguments) {
    // TODO: This is temp fix!!!!!
    _client = startSSH(Uri.base);
    _remoteStdout.stream.listen(stdout.add);
    stdin.cast<Uint8List>().listen(_client.sendChannelData);

    if (!Platform.isWindows) {
      _winchSignalSubscription = ProcessSignal.sigwinch.watch().listen((_) {
        onLocalTerminalSizeChange();
      });
    }
  }

  final _remoteStdout = StreamController<List<int>>();

  late SSHClient _client;

  StreamSubscription<ProcessSignal>? _winchSignalSubscription;

  SSHClient startSSH(Uri url, {String? password, bool verbose = false}) {
    return SSHClient(
      hostname: url,
      username: url.userInfo,
      // password: password,
      print: verbose ? print : null,
      debugPrint: verbose ? print : null,
      tracePrint: verbose ? print : null,
      response: onResponse,
      termvar: Platform.environment['TERM'] ?? 'xterm',
      success: onSuccess,
      loadIdentity: loadIdentity,
      onPasswordRequest: onPasswordRequest,
      onUserauthRequest: onUserauthRequest,
      disconnected: onDisconnect,
    );
  }

  SSHIdentity? loadIdentity() {
    final home = Platform.environment['HOME'];
    final keyFile = File('$home/.ssh/id_rsa');

    if (keyFile.existsSync()) {
      return SSHIdentity.fromPem(keyFile.readAsStringSync());
    }
  }

  String onPasswordRequest() {
    final url = '${args.user}@${args.host}';
    final password = readline("$url's password: ", echo: false);
    if (password == null) {
      quit('No password provided.', exitCode: 1);
    }
    return password;
  }

  List<String> onUserauthRequest(SSHUserauthRequest request) {
    if (request.name != null && request.name!.isNotEmpty) {
      print(request.name);
    }
    if (request.instruction != null && request.instruction!.isNotEmpty) {
      print(request.instruction);
    }
    final responses = <String>[];
    for (var prompt in request.prompts) {
      final password = readline(prompt.prompt, echo: prompt.echo);
      if (password == null) {
        quit('No ${prompt.prompt} provided.', exitCode: 1);
      }
      responses.add(password);
    }
    return responses;
  }

  void onSuccess() {
    // console.clearScreen();
    // console.resetCursorPosition();
    console.rawMode = true;
    _client.setTerminalWindowSize(console.windowWidth, console.windowHeight);
  }

  void onResponse(Uint8List data) {
    stdout.add(data);
  }

  Future<void> onDisconnect() async {
    _winchSignalSubscription?.cancel();
    await _remoteStdout.close();
    console.rawMode = false;
    print('Disconnected.');
    exit(0);
  }

  void onLocalTerminalSizeChange() {
    _client.setTerminalWindowSize(
      console.windowWidth,
      console.windowHeight,
    );
  }
}

Never printUsageAndExit([int exitCode = 0]) {
  print(getUsage());
  exit(exitCode);
}
