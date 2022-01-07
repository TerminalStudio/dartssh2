import 'dart:async';
import 'dart:io';

import 'package:dart_console/dart_console.dart';

String readline(String message, {bool echo = true}) {
  stdin.echoMode = echo;
  stdout.write(message);
  final result = stdin.readLineSync();
  print(''); // line break
  stdin.echoMode = true;
  if (result == null) exit(1);
  return result;
}

Never quit(String message, {int exitCode = 0}) {
  print(message);
  exit(exitCode);
}

String? get homeDir {
  switch (Platform.operatingSystem) {
    case 'linux':
    case 'macos':
      return Platform.environment['HOME'];
    case 'windows':
      return Platform.environment['USERPROFILE'];
    default:
      return null;
  }
}

class Observable<T> {
  final List<Function()> listeners = [];

  void addListener(Function() listener) {
    listeners.add(listener);
  }

  void removeListener(Function() listener) {
    listeners.remove(listener);
  }

  void notifyListeners() {
    for (final listener in listeners) {
      listener();
    }
  }
}

class TerminalResizeNotifier with Observable {
  TerminalResizeNotifier() {
    final event = Platform.isWindows
        ? _windowsResizeEvents()
        : ProcessSignal.sigwinch.watch();

    subscription = event.listen((_) => notifyListeners());
  }

  late final StreamSubscription subscription;

  void dispose() {
    subscription.cancel();
  }
}

Stream<void> _windowsResizeEvents() async* {
  final console = Console();
  var width = console.windowWidth;
  var height = console.windowHeight;
  while (true) {
    final newWidth = console.windowWidth;
    final newHeight = console.windowHeight;
    if (newWidth != width || newHeight != height) {
      width = newWidth;
      height = newHeight;
      yield null;
    }
    await Future.delayed(Duration(milliseconds: 100));
  }
}

extension StringX on String {
  String indent(int indentation) {
    return split('\n').map((line) => ' ' * indentation + line).join('\n');
  }
}

extension IntX on int {
  String toHex() {
    return toRadixString(16);
  }

  String toBinary() {
    return toRadixString(2);
  }

  String toOctal() {
    return toRadixString(8);
  }
}
