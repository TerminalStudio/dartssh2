import 'dart:io';

import 'package:args/args.dart';

final parser = ArgParser()
  ..addOption('key', abbr: 'k')
  ..addOption('key-passphrase', abbr: 'K')
  ..addOption('command', abbr: 'c')
  ..addFlag('help', abbr: 'h', negatable: false)
  ..addFlag('verbose', abbr: '', negatable: false);

class SSHCommandArgs {
  final String host;
  final int port;
  final String user;
  // final String key;
  // final String keyPassphrase;
  // final String command;
  final bool verbose;

  SSHCommandArgs({
    required this.host,
    required this.port,
    required this.user,
    // required this.key,
    // required this.keyPassphrase,
    // required this.command,
    required this.verbose,
  });
}

SSHCommandArgs mustParseArgs(List<String> args) {
  final results = parser.parse(args);
  if (results['help']) {
    print(parser.usage);
    exit(0);
  }

  if (results.rest.length != 1) {
    print(parser.usage);
    exit(1);
  }

  final urlString = results.rest.first.startsWith('ssh://')
      ? results.rest.first
      : 'ssh://' + results.rest.first;

  final url = Uri.tryParse(urlString);
  if (url == null) {
    print('Invalid URL: $urlString');
    exit(1);
  }

  return SSHCommandArgs(
    host: url.host,
    port: url.port,
    user: url.userInfo,
    // key: results['key'],
    // keyPassphrase: results['key-passphrase'],
    // command: results['command'],
    verbose: results['verbose'],
  );
}

String getUsage() {
  final builder = StringBuffer();
  builder.writeln('Usage: dartssh [options] [user@]host[:port]');
  builder.writeln();
  builder.writeln('Options:');
  builder.writeln(parser.usage);
  return builder.toString();
}
