import 'package:dartssh2/dartssh2.dart';
import 'package:test/test.dart';

void main() {
  test(
      'SSHUserInfoRequest and related userauth classes are exported by dartssh2.dart',
      () {
    final prompt = SSHUserInfoPrompt('Password:', false);
    expect(prompt.promptText, equals('Password:'));
    expect(prompt.echo, isFalse);

    final request = SSHUserInfoRequest('Title', 'Instruction', [prompt]);
    expect(request.name, equals('Title'));
    expect(request.instruction, equals('Instruction'));
    expect(request.prompts.length, equals(1));
    expect(request.prompts.first.promptText, equals('Password:'));

    final changePasswordResponse = SSHChangePasswordResponse('old', 'new');
    expect(changePasswordResponse.oldPassword, equals('old'));
    expect(changePasswordResponse.newPassword, equals('new'));

    expect(
        SSHAuthMethod.keyboardInteractive.name, equals('keyboard-interactive'));
  });
}
