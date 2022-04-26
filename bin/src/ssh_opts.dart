import 'dart:io';

import 'package:args/args.dart';

import 'utils.dart';

final _destinationPattern =
    RegExp(r'^(?:(?<user>.+)@)?(?<host>[^:]+)(?::(?<port>\d+))?$');

class SSHDestination {
  final String? user;

  final String host;

  final int port;

  SSHDestination({
    required this.user,
    required this.host,
    required this.port,
  });

  static SSHDestination? tryParse(String dest) {
    final match = _destinationPattern.firstMatch(dest);
    if (match == null) return null;
    return SSHDestination(
      user: match.namedGroup('user'),
      host: match.namedGroup('host')!,
      port: match.namedGroup('port') != null
          ? int.parse(match.namedGroup('port')!)
          : 22,
    );
  }
}

abstract class SSHConnectOpts {
  SSHDestination get target;

  bool get verbose;
}

class SSHOpts with SSHConnectOpts {
  @override
  final SSHDestination target;

  @override
  final bool verbose;

  final bool doNotExecute;

  final List<String>? command;

  final SSHForwardConfig? forwardLocal;

  final SSHForwardConfig? forwardRemote;

  SSHOpts(
    this.target, {
    this.verbose = false,
    this.doNotExecute = false,
    this.command,
    this.forwardLocal,
    this.forwardRemote,
  });
}

class SSHForwardConfig {
  final String? sourceHost;
  final int sourcePort;
  final String destinationHost;
  final int destinationPort;

  SSHForwardConfig(
    this.sourceHost,
    this.sourcePort,
    this.destinationHost,
    this.destinationPort,
  );

  factory SSHForwardConfig.parse(String line) {
    final parts = line.split(':');
    if (parts.length != 3 && parts.length != 4) {
      throw FormatException('Invalid forwarding line: $line');
    }

    final hasSourceAddress = parts.length == 4;
    final sourceAddress = hasSourceAddress ? parts.removeAt(0) : null;
    final sourcePort = int.parse(parts.removeAt(0));
    final destinationAddress = parts.removeAt(0);
    final destinationPort = int.parse(parts.removeAt(0));

    return SSHForwardConfig(
      sourceAddress,
      sourcePort,
      destinationAddress,
      destinationPort,
    );
  }

  @override
  String toString() {
    final parts = <String>[];
    if (sourceHost != null) parts.add(sourceHost!);
    parts.add('$sourcePort:$destinationHost:$destinationPort');
    return parts.join(':');
  }
}

class SFTPOpts with SSHConnectOpts {
  @override
  final SSHDestination target;

  @override
  final bool verbose;

  SFTPOpts(
    this.target, {
    this.verbose = false,
  });
}

class DartSSH {
  static final _optionParser = ArgParser(allowTrailingOptions: false)
    ..addOption('key', abbr: 'k')
    ..addOption('key-passphrase', abbr: 'K')
    ..addOption('forward-local', abbr: 'L')
    ..addOption('forward-remote', abbr: 'R')
    ..addFlag('do-not-execute', abbr: 'N')
    ..addFlag('help', abbr: 'h', negatable: false)
    ..addFlag('verbose', abbr: 'v', negatable: false);

  static String get usage {
    final builder = StringBuffer();
    builder.writeln('Usage: dartssh [options] [user@]host[:port]');
    builder.writeln();
    builder.writeln('Options:');
    builder.writeln(_optionParser.usage.indent(4));
    return builder.toString();
  }

  static SSHOpts parseArgs(List<String> args) {
    final opts = _optionParser.parse(args);

    if (opts['help']) {
      print(usage);
      exit(0);
    }

    if (opts.rest.isEmpty) {
      print(usage);
      exit(1);
    }

    final url = opts.rest.first;
    final destination = SSHDestination.tryParse(url);

    if (destination == null) {
      print('Invalid URL: $url');
      exit(1);
    }

    final command = opts.rest.length > 1 ? opts.rest.sublist(1) : null;

    return SSHOpts(
      destination,
      // key: opts['key'],
      // keyPassphrase: opts['key-passphrase'],
      doNotExecute: opts['do-not-execute'],
      command: command,
      forwardLocal: opts['forward-local'] != null
          ? SSHForwardConfig.parse(opts['forward-local'])
          : null,
      forwardRemote: opts['forward-remote'] != null
          ? SSHForwardConfig.parse(opts['forward-remote'])
          : null,
      verbose: opts['verbose'],
    );
  }
}

class DartSFTP {
  static final _optionParser = ArgParser()
    ..addOption('key', abbr: 'k')
    ..addOption('key-passphrase', abbr: 'K')
    ..addOption('command', abbr: 'c')
    ..addFlag('help', abbr: 'h', negatable: false)
    ..addFlag('verbose', abbr: 'v', negatable: false);

  static String get usage {
    final builder = StringBuffer();
    builder.writeln('Usage: dartsftp [options] [user@]host[:port]');
    builder.writeln();
    builder.writeln('Options:');
    builder.writeln(_optionParser.usage.indent(4));
    return builder.toString();
  }

  static SFTPOpts parseArgs(List<String> args) {
    final opts = _optionParser.parse(args);

    if (opts['help']) {
      print(usage);
      exit(0);
    }

    if (opts.rest.length != 1) {
      print(usage);
      exit(1);
    }

    final url = opts.rest.first;
    final destination = SSHDestination.tryParse(url);

    if (destination == null) {
      print('Invalid URL: $url');
      exit(1);
    }

    return SFTPOpts(
      destination,
      // key: opts['key'],
      // keyPassphrase: opts['key-passphrase'],
      // command: opts['command'],
      verbose: opts['verbose'],
    );
  }
}
