import 'dart:io';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/message/msg_channel.dart';

/// A honeypot that accepts all passwords and public-keys
Future<SSHClient> getHoneypotClient() async {
  return SSHClient(
    await SSHSocket.connect('test.rebex.net', 22),
    username: 'demo',
    onPasswordRequest: () => 'password',
  );
}

/// A honeypot that denies all passwords and public-keys
Future<SSHClient> getDenyingHoneypotClient() async {
  return SSHClient(
    await SSHSocket.connect('honeypot.terminal.studio', 2023),
    username: 'root',
    onPasswordRequest: () => 'random',
  );
}

/// A test server provided by test.rebex.net.
Future<SSHClient> getTestClient() async {
  return SSHClient(
    await SSHSocket.connect('test.rebex.net', 22),
    username: 'demo',
    onPasswordRequest: () => 'password',
  );
}

Future<List<SSHKeyPair>> getTestKeyPairs() async {
  final ed25519Private = fixture('ssh-ed25519/id_ed25519');
  return SSHKeyPair.fromPem(ed25519Private);
}

/// Get the contents of a test fixture.
///
/// The path is relative to the test/fixtures directory.
String fixture(String path) {
  return File('test/fixtures/$path').readAsStringSync();
}

/// Create a [SSH_Message_Channel_Close] message.
Uint8List createChannelCloseMessage(int recipientChannel) {
  final message = SSH_Message_Channel_Close(
    recipientChannel: recipientChannel,
  );
  return message.encode();
}
