import 'dart:io';

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
