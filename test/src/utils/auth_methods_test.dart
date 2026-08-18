import 'package:dartssh2/src/ssh_userauth.dart';
import 'package:dartssh2/src/utils/auth_methods.dart';
import 'package:test/test.dart';

void main() {
  List<SSHAuthMethod> select({
    required List<SSHAuthMethod> preferred,
    required List<String> server,
    required Set<SSHAuthMethod> available,
    void Function(String)? onNote,
  }) {
    return selectContinuableAuthMethods(
      preferredMethods: preferred,
      serverMethods: server,
      availableMethods: available,
      onNote: onNote,
    );
  }

  test('uses the server list as an allow-list, not a preference list', () {
    expect(
      select(
        preferred: [
          SSHAuthMethod.publicKey,
          SSHAuthMethod.password,
          SSHAuthMethod.keyboardInteractive,
        ],
        server: ['keyboard-interactive', 'password', 'publickey'],
        available: {
          SSHAuthMethod.publicKey,
          SSHAuthMethod.password,
          SSHAuthMethod.keyboardInteractive,
        },
      ),
      [
        SSHAuthMethod.publicKey,
        SSHAuthMethod.password,
        SSHAuthMethod.keyboardInteractive,
      ],
    );
  });

  test('drops methods that have no remaining client-side attempt', () {
    expect(
      select(
        preferred: [
          SSHAuthMethod.publicKey,
          SSHAuthMethod.hostbased,
          SSHAuthMethod.password,
        ],
        server: ['publickey', 'hostbased', 'password'],
        available: {SSHAuthMethod.password},
      ),
      [SSHAuthMethod.password],
    );
  });

  test('keeps identity methods while another identity remains', () {
    expect(
      select(
        preferred: [
          SSHAuthMethod.publicKey,
          SSHAuthMethod.hostbased,
          SSHAuthMethod.password,
        ],
        server: ['password', 'hostbased', 'publickey'],
        available: {
          SSHAuthMethod.publicKey,
          SSHAuthMethod.hostbased,
          SSHAuthMethod.password,
        },
      ),
      [
        SSHAuthMethod.publicKey,
        SSHAuthMethod.hostbased,
        SSHAuthMethod.password,
      ],
    );
  });

  test('does not duplicate a method repeated by the server', () {
    expect(
      select(
        preferred: [SSHAuthMethod.publicKey, SSHAuthMethod.password],
        server: ['publickey', 'publickey', 'password'],
        available: {SSHAuthMethod.publicKey, SSHAuthMethod.password},
      ),
      [SSHAuthMethod.publicKey, SSHAuthMethod.password],
    );
  });

  test('reports unknown and invalid continuable methods', () {
    final notes = <String>[];

    expect(
      select(
        preferred: SSHAuthMethod.values,
        server: ['none', 'gssapi-with-mic'],
        available: SSHAuthMethod.values.toSet(),
        onNote: notes.add,
      ),
      isEmpty,
    );
    expect(notes, hasLength(2));
    expect(notes[0], contains('none'));
    expect(notes[1], contains('gssapi-with-mic'));
  });
}
