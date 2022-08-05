import 'dart:io';
import 'dart:typed_data';

import 'package:dart_console/dart_console.dart';
import 'package:dartssh2/dartssh2.dart';

import 'src/ssh_opts.dart';
import 'src/ssh_shared.dart';

final console = Console();

void main(List<String> args) async {
  final options = DartSFTP.parseArgs(args);
  await repl(options);
}

Future<void> repl(SFTPOpts options) async {
  final client = await startClientWithOpts(options);
  final session = await client.sftp();
  final homeDir = (await session.absolute('.')).split('/');
  final context = SFTPContext(session, options, homeDir, homeDir);
  print('Connected to ${options.target.host}');

  while (true) {
    stdout.write('> ');
    final line = console.readLine(cancelOnEOF: true);
    if (line == null) exit(0);
    await context.eval(line);
  }
}

class SFTPContext {
  final commands = SFTPCommandRegistry.fromCommands([
    /* Remote */

    SFTPCommandLs(),
    SFTPCommandCd(),
    SFTPCommandGet(),
    SFTPCommandPut(),
    SFTPCommandMkdir(),
    SFTPCommandRmdir(),
    SFTPCommandRm(),
    SFTPCommandMv(),
    SFTPCommandPwd(),

    /* Local */

    SFTPCommandLls(),
    SFTPCommandLpwd(),
    SFTPCommandHelp(),
    SFTPCommandEscape(),
    SFTPCommandExit(),
  ]);

  SFTPContext(this.sftp, this.options, this.homeDir, this.workingDir);

  final SftpClient sftp;

  final SFTPOpts options;

  final List<String> homeDir;

  List<String> workingDir;

  Future<void> eval(String command) async {
    final args = command.trim().replaceAll(RegExp(r'\s+'), ' ').split(' ');
    final name = args.removeAt(0);

    if (name.startsWith('!') && name.length > 1) {
      final executable = name.substring(1);
      return evalShell(executable, args);
    }

    return evalCommand(name, args);
  }

  Future<void> evalShell(String executable, List<String> arguments) async {
    final result = await Process.start(
      executable,
      arguments,
      mode: ProcessStartMode.inheritStdio,
    );
    if (await result.exitCode != 0) {
      print('Error: ${result.exitCode}');
    }
  }

  Future<void> evalCommand(String command, List<String> arguments) async {
    final func = commands.lookup(command);
    if (func == null) {
      print('Unknown command: $command');
      return;
    }
    await func(this, arguments);
  }

  String remotePath(String path) {
    if (path.startsWith('/')) {
      return path;
    }

    return [...workingDir, ...path.split('/')].join('/');
  }
}

abstract class SFTPCommand {
  String get name;

  String get usage;

  String get help;

  Future<void> call(SFTPContext ctx, List<String> args);
}

class SFTPCommandRegistry {
  SFTPCommandRegistry();

  SFTPCommandRegistry.fromCommands(List<SFTPCommand> commands) {
    for (final command in commands) {
      register(command);
    }
  }

  final _commands = <String, SFTPCommand>{};

  void register(SFTPCommand command) {
    _commands[command.name] = command;
  }

  SFTPCommand? lookup(String name) {
    return _commands[name];
  }

  List<SFTPCommand> get commands => _commands.values.toList();
}

class SFTPCommandLs implements SFTPCommand {
  @override
  final name = 'ls';

  @override
  final usage = 'ls [path]';

  @override
  final help = 'List files in the remote directory';

  @override
  Future<void> call(SFTPContext ctx, List<String> args) async {
    late final String path;

    if (args.isEmpty) {
      path = '.';
    } else if (args.length == 1) {
      path = args.first;
    } else {
      print('Usage: $usage');
      return;
    }

    final entries = await ctx.sftp.listdir(ctx.remotePath(path));
    for (final entry in entries) {
      print(entry.longname);
    }
  }
}

class SFTPCommandCd implements SFTPCommand {
  @override
  final name = 'cd';

  @override
  final usage = 'cd [path]';

  @override
  final help = 'Change the remote directory';

  @override
  Future<void> call(SFTPContext ctx, List<String> args) async {
    if (args.isEmpty) {
      ctx.workingDir = ctx.homeDir.toList();
    } else if (args.length == 1) {
      final path = ctx.remotePath(args[0]);
      try {
        final absolutePath = await ctx.sftp.absolute(path);
        final stat = await ctx.sftp.stat(absolutePath);
        if (stat.isDirectory != true) {
          print('$path is not a directory');
          return;
        }
        ctx.workingDir = absolutePath.split('/');
      } on SftpStatusError catch (e) {
        print('Error: ${e.message}');
        return;
      }
    } else {
      print('Usage: cd [path]');
      return;
    }
  }
}

class SFTPCommandGet implements SFTPCommand {
  @override
  final name = 'get';

  @override
  final usage = 'get <remote-path> [local-path]';

  @override
  final help = 'Download a file from the remote directory';

  @override
  Future<void> call(SFTPContext ctx, List<String> args) async {
    if (args.isEmpty) {
      print('Usage: $usage');
      return;
    }

    final remotePath = ctx.remotePath(args[0]);
    final localPath = args.length > 1 ? args[1] : remotePath.split('/').last;

    late final SftpFile file;
    late final SftpFileAttrs fileStat;
    try {
      file = await ctx.sftp.open(remotePath, mode: SftpFileOpenMode.read);
      fileStat = await file.stat();
    } on SftpStatusError catch (e) {
      print('Error: ${e.message}');
      return;
    }

    final localFile = File(localPath);
    await localFile.create(recursive: true);

    await file
        .read(onProgress: (bytes) => _reportProgress(bytes, fileStat.size))
        .cast<List<int>>()
        .pipe(localFile.openWrite());

    stdout.writeln();
  }
}

class SFTPCommandPut implements SFTPCommand {
  @override
  final name = 'put';

  @override
  final usage = 'put <local-path> [remote-path]';

  @override
  final help = 'Upload a file to the remote directory';

  @override
  Future<void> call(SFTPContext ctx, List<String> args) async {
    if (args.isEmpty) {
      print('Usage: $usage');
      return;
    }

    final localPath = args[0];
    final remotePath = args.length > 1 ? args[1] : localPath.split('/').last;

    late final SftpFile remoteFile;
    try {
      remoteFile = await ctx.sftp.open(
        ctx.remotePath(remotePath),
        mode: SftpFileOpenMode.write | SftpFileOpenMode.create,
      );
    } on SftpStatusError catch (e) {
      print('Error: ${e.message}');
      return;
    }

    final localFile = File(localPath);
    final localFileStat = await localFile.stat();
    final file = localFile.openRead();

    await remoteFile.write(
      file.cast<Uint8List>(),
      onProgress: (bytes) => _reportProgress(bytes, localFileStat.size),
    );

    stdout.writeln();
  }
}

class SFTPCommandMkdir implements SFTPCommand {
  @override
  final name = 'mkdir';

  @override
  final usage = 'mkdir <path>';

  @override
  final help = 'Create a directory on the remote directory';

  @override
  Future<void> call(SFTPContext ctx, List<String> args) async {
    if (args.isEmpty) {
      print('Usage: $usage');
      return;
    }

    final path = ctx.remotePath(args[0]);

    try {
      await ctx.sftp.mkdir(path);
    } on SftpStatusError catch (e) {
      print('Error: ${e.message}');
      return;
    }
  }
}

class SFTPCommandRmdir implements SFTPCommand {
  @override
  final name = 'rmdir';

  @override
  final usage = 'rmdir <path>';

  @override
  final help = 'Remove a directory on the remote directory';

  @override
  Future<void> call(SFTPContext ctx, List<String> args) async {
    if (args.isEmpty) {
      print('Usage: $usage');
      return;
    }

    final path = ctx.remotePath(args[0]);

    try {
      await ctx.sftp.rmdir(path);
    } on SftpStatusError catch (e) {
      print('Error: ${e.message}');
      return;
    }
  }
}

class SFTPCommandRm implements SFTPCommand {
  @override
  final name = 'rm';

  @override
  final usage = 'rm <path>';

  @override
  final help = 'Remove a file on the remote directory';

  @override
  Future<void> call(SFTPContext ctx, List<String> args) async {
    if (args.isEmpty) {
      print('Usage: $usage');
      return;
    }

    final path = ctx.remotePath(args[0]);

    try {
      await ctx.sftp.remove(path);
    } on SftpStatusError catch (e) {
      print('Error: ${e.message}');
      return;
    }
  }
}

class SFTPCommandMv implements SFTPCommand {
  @override
  final name = 'mv';

  @override
  final usage = 'mv <source> <destination>';

  @override
  final help = 'Move a file or directory on the remote directory';

  @override
  Future<void> call(SFTPContext ctx, List<String> args) async {
    if (args.length != 2) {
      print('Usage: $usage');
      return;
    }

    final source = ctx.remotePath(args[0]);
    final destination = ctx.remotePath(args[1]);

    try {
      await ctx.sftp.rename(source, destination);
    } on SftpStatusError catch (e) {
      print('Error: ${e.message}');
      return;
    }
  }
}

class SFTPCommandPwd implements SFTPCommand {
  @override
  final name = 'pwd';

  @override
  final usage = 'pwd';

  @override
  final help = 'Print the current remote directory';

  @override
  Future<void> call(SFTPContext ctx, List<String> args) async {
    final directory = ctx.workingDir.join('/');
    print('Remote working directory: $directory');
  }
}

class SFTPCommandLls implements SFTPCommand {
  @override
  final name = 'lls';

  @override
  final usage = 'lls [path]';

  @override
  final help = 'List files in the local directory';

  @override
  Future<void> call(SFTPContext ctx, List<String> args) async {
    final entries = Directory.current.list();
    await for (final entry in entries) {
      print(entry.path);
    }
  }
}

class SFTPCommandLpwd implements SFTPCommand {
  @override
  final name = 'lpwd';

  @override
  final usage = 'lpwd';

  @override
  final help = 'Print the current local directory';

  @override
  Future<void> call(SFTPContext ctx, List<String> args) async {
    print('Local working directory: ${Directory.current.path}');
  }
}

class SFTPCommandHelp implements SFTPCommand {
  @override
  final name = 'help';

  @override
  final usage = 'help';

  @override
  final help = 'Print this help message';

  @override
  Future<void> call(SFTPContext ctx, List<String> args) async {
    print('Available commands:');
    for (final command in ctx.commands.commands) {
      print('${command.usage.padRight(25)} ${command.help}');
    }
  }
}

class SFTPCommandEscape implements SFTPCommand {
  @override
  final name = '!';

  @override
  final usage = '!<command>';

  @override
  final help = 'Escape to the local shell';

  @override
  Future<void> call(SFTPContext ctx, List<String> args) async {
    if (args.isEmpty) {
      print('Usage: !<command>');
      return;
    }
    await Process.start(
      args[0],
      args.sublist(1),
      mode: ProcessStartMode.inheritStdio,
    );
  }
}

class SFTPCommandExit implements SFTPCommand {
  @override
  final name = 'exit';

  @override
  final usage = 'exit';

  @override
  final help = 'Exit the program';

  @override
  Future<void> call(SFTPContext ctx, List<String> args) async {
    exit(0);
  }
}

void _reportProgress(int bytesRead, int? total) {
  if (total != null) {
    final percent = (bytesRead / total * 100).toStringAsFixed(2);
    console.write('${'$percent%'.padLeft(7)}  ');
  }
  console.writeLine('$bytesRead/${total ?? '??'} bytes');
}
