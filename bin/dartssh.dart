import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:args/args.dart';
import 'package:dart_console/dart_console.dart';
import 'package:dartssh2/dartssh2.dart';

final console = Console();

void main(List<String> arguments) {
  return runApp(arguments);
}

void runApp(List<String> arguments) {
  final argParser = buildArgParser();
  final args = argParser.parse(arguments);

  if (args['help']) {
    printUsageAndExit(0);
  }

  if (args.rest.length != 1) {
    printUsageAndExit(1);
  }

  final urlString = args.rest.first.startsWith('ssh://')
      ? args.rest.first
      : 'ssh://' + args.rest.first;

  var url = Uri.tryParse(urlString);

  if (url == null) {
    print('Invalid URL: $urlString');
    exit(1);
  }

  if (!url.hasPort) {
    url = url.replace(port: 22);
  }

  startSSH(url, verbose: args['verbose']);
}

ArgParser buildArgParser() {
  final parser = ArgParser();
  parser.addFlag('help', abbr: 'h', help: 'Show this help message.');
  parser.addFlag('verbose', abbr: 'v', help: 'Verbose output.');
  return parser;
}

void printUsage(ArgParser parser) {
  print('Usage: dartssh [options] [user@]host[:port]');
  print('');
  print('Options:');
  print(parser.usage);
}

Never printUsageAndExit([int exitCode = 0]) {
  printUsage(buildArgParser());
  exit(exitCode);
}

void startSSH(Uri url, {String? password, bool verbose = false}) {
  StreamSubscription<ProcessSignal>? winchSignalSubscription;
  late SSHClient client;

  final remoteStdout = StreamController<List<int>>();
  remoteStdout.stream.listen(stdout.add);

  client = SSHClient(
    hostport: url,
    username: url.userInfo,
    print: verbose ? print : null,
    debugPrint: verbose ? print : null,
    tracePrint: verbose ? print : null,
    // password: password,
    response: (data) {
      remoteStdout.sink.add(data);
    },
    termvar: Platform.environment['TERM'] ?? 'xterm',
    success: () {
      // console.clearScreen();
      // console.resetCursorPosition();
      console.rawMode = true;
      client.setTerminalWindowSize(console.windowWidth, console.windowHeight);
    },
    loadIdentity: () {
      final home = Platform.environment['HOME'];
      final keyFile = File('$home/.ssh/id_rsa');

      if (keyFile.existsSync()) {
        return SSHIdentity.fromPem(keyFile.readAsStringSync());
      }
    },
    onPasswordRequest: () {
      final password = readline("$url's password: ", echo: false);
      if (password == null) {
        quit('No password provided.', exitCode: 1);
      }
      return password;
    },
    onUserauthRequest: (request) {
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
    },
    disconnected: () async {
      winchSignalSubscription?.cancel();
      await remoteStdout.close();
      console.rawMode = false;
      print('Disconnected');
      exit(0);
    },
  );

  if (!Platform.isWindows) {
    winchSignalSubscription = ProcessSignal.sigwinch.watch().listen((_) {
      client.setTerminalWindowSize(console.windowWidth, console.windowHeight);
    });
  }

  stdin.listen((data) {
    client.sendChannelData(data as Uint8List);
  });
}

String? readline(String message, {bool echo = true}) {
  stdin.echoMode = echo;
  stdout.write(message);
  final result = stdin.readLineSync();
  print(''); // line break
  stdin.echoMode = true;
  return result;
}

Never quit(String message, {int exitCode = 0}) {
  print(message);
  exit(exitCode);
}
