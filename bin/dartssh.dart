import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:args/args.dart';
import 'package:dart_console/dart_console.dart';
import 'package:dartssh2/dartssh2.dart';

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
  final console = Console();

  final remoteStdout = StreamController<List<int>>();
  remoteStdout.stream.listen(stdout.add);

  client = SSHClient(
    hostport: url,
    login: url.userInfo,
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
    getPassword: () {
      stdout.write('Enter your password: ');
      final password = console.readLine();
      if (password == null) throw Exception('No password provided');
      return utf8.encode(password) as Uint8List;
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
