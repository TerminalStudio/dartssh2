import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/message/msg_userauth.dart';
import 'package:dartssh2/src/ssh_message.dart';
import 'package:test/test.dart';

void main() {
  final publicKey = Uint8List.fromList(List.generate(32, (i) => i));
  final signature = Uint8List.fromList(List.generate(64, (i) => 255 - i));

  group('SSH_Message_Userauth_Request', () {
    test('none round-trips', () {
      final original = SSH_Message_Userauth_Request.none(user: 'root');
      final decoded = SSH_Message_Userauth_Request.decode(original.encode());

      expect(SSHMessage.readMessageId(original.encode()), 50);
      expect(decoded.user, 'root');
      expect(decoded.methodName, 'none');
      expect(decoded.serviceName, 'ssh-connection');
      expect(decoded.toString(), contains('methodName: none'));
    });

    test('password round-trips', () {
      final original = SSH_Message_Userauth_Request.password(
        user: 'demo',
        password: 'hunter2',
      );
      final decoded = SSH_Message_Userauth_Request.decode(original.encode());

      expect(decoded.user, 'demo');
      expect(decoded.methodName, 'password');
      expect(decoded.password, 'hunter2');
      expect(decoded.oldPassword, isNull);
    });

    test('password change round-trips without swapping the passwords', () {
      // RFC 4252 §8 sends the old password first and the new one second.
      final original = SSH_Message_Userauth_Request.newPassword(
        user: 'demo',
        oldPassword: 'old-secret',
        newPassword: 'new-secret',
      );
      final decoded = SSH_Message_Userauth_Request.decode(original.encode());

      expect(decoded.oldPassword, 'old-secret');
      expect(decoded.password, 'new-secret');
    });

    test('signed publickey round-trips', () {
      final original = SSH_Message_Userauth_Request.publicKey(
        username: 'demo',
        publicKeyAlgorithm: 'ssh-ed25519',
        publicKey: publicKey,
        signature: signature,
      );
      final decoded = SSH_Message_Userauth_Request.decode(original.encode());

      expect(decoded.publicKeyAlgorithm, 'ssh-ed25519');
      expect(decoded.publicKey, publicKey);
      expect(decoded.signature, signature);
    });

    test('unsigned publickey probe round-trips', () {
      // The probe of RFC 4252 §7.8 carries no signature, and the boolean in
      // front of the algorithm name is what says so.
      final original = SSH_Message_Userauth_Request.publicKey(
        username: 'demo',
        publicKeyAlgorithm: 'ssh-ed25519',
        publicKey: publicKey,
        signature: null,
      );
      final decoded = SSH_Message_Userauth_Request.decode(original.encode());

      expect(decoded.publicKeyAlgorithm, 'ssh-ed25519');
      expect(decoded.publicKey, publicKey);
      expect(decoded.signature, isNull);
    });

    test('keyboard-interactive round-trips', () {
      final original = SSH_Message_Userauth_Request.keyboardInteractive(
        user: 'demo',
        languageTag: 'en-US',
        submethods: 'pam',
      );
      final decoded = SSH_Message_Userauth_Request.decode(original.encode());

      expect(decoded.methodName, 'keyboard-interactive');
      expect(decoded.languageTag, 'en-US');
      expect(decoded.submethods, 'pam');
    });

    test('rejects an unknown method on encode and decode', () {
      final unknown = SSH_Message_Userauth_Request(
        user: 'demo',
        serviceName: 'ssh-connection',
        methodName: 'hostbased',
      );

      expect(unknown.encode, throwsUnimplementedError);

      // Build the same message by hand so decode sees the unknown method.
      final writer = SSHMessageWriter();
      writer.writeUint8(SSH_Message_Userauth_Request.messageId);
      writer.writeUtf8('demo');
      writer.writeUtf8('ssh-connection');
      writer.writeUtf8('hostbased');

      expect(
        () => SSH_Message_Userauth_Request.decode(writer.takeBytes()),
        throwsUnimplementedError,
      );
    });
  });

  group('SSH_Message_Userauth_Failure', () {
    test('round-trips', () {
      final original = SSH_Message_Userauth_Failure(
        methodsLeft: const ['publickey', 'password'],
        partialSuccess: true,
      );
      final decoded = SSH_Message_Userauth_Failure.decode(original.encode());

      expect(SSHMessage.readMessageId(original.encode()), 51);
      expect(decoded.methodsLeft, ['publickey', 'password']);
      expect(decoded.partialSuccess, isTrue);
      expect(decoded.toString(), contains('partialSuccess: true'));
    });

    test('defaults partialSuccess to false', () {
      final original =
          SSH_Message_Userauth_Failure(methodsLeft: const ['password']);

      expect(
        SSH_Message_Userauth_Failure.decode(original.encode()).partialSuccess,
        isFalse,
      );
    });
  });

  group('SSH_Message_Userauth_Success', () {
    test('round-trips', () {
      final original = SSH_Message_Userauth_Success();
      final decoded = SSH_Message_Userauth_Success.decode(original.encode());

      expect(SSHMessage.readMessageId(original.encode()), 52);
      expect(decoded, isA<SSH_Message_Userauth_Success>());
      expect(decoded.toString(), 'SSH_Message_Userauth_Success()');
    });
  });

  group('SSH_Message_Userauth_Banner', () {
    test('round-trips', () {
      final original = SSH_Message_Userauth_Banner(
        message: 'Authorised users only',
        language: 'en',
      );
      final decoded = SSH_Message_Userauth_Banner.decode(original.encode());

      expect(SSHMessage.readMessageId(original.encode()), 53);
      expect(decoded.message, 'Authorised users only');
      expect(decoded.language, 'en');
      expect(decoded.toString(), contains('Authorised users only'));
    });

    test('preserves non-ASCII banners', () {
      final original = SSH_Message_Userauth_Banner(message: 'contraseña 🔐');

      expect(
        SSH_Message_Userauth_Banner.decode(original.encode()).message,
        'contraseña 🔐',
      );
    });
  });

  group('SSH_Message_Userauth_Passwd_ChangeReq', () {
    test('round-trips', () {
      final original = SSH_Message_Userauth_Passwd_ChangeReq(
        prompt: 'Your password has expired',
      );
      final decoded =
          SSH_Message_Userauth_Passwd_ChangeReq.decode(original.encode());

      expect(SSHMessage.readMessageId(original.encode()), 60);
      expect(decoded.prompt, 'Your password has expired');
      expect(decoded.toString(), contains('expired'));
    });
  });

  group('SSH_Message_Userauth_PK_Ok', () {
    test('round-trips', () {
      final original = SSH_Message_Userauth_PK_Ok(
        publicKeyAlgorithm: 'ssh-ed25519',
        publicKey: publicKey,
      );
      final decoded = SSH_Message_Userauth_PK_Ok.decode(original.encode());

      expect(SSHMessage.readMessageId(original.encode()), 60);
      expect(decoded.publicKeyAlgorithm, 'ssh-ed25519');
      expect(decoded.publicKey, publicKey);
      expect(decoded.toString(), contains('ssh-ed25519'));
    });
  });

  group('SSH_Message_Userauth_InfoRequest', () {
    test('round-trips with prompts', () {
      final original = SSH_Message_Userauth_InfoRequest(
        name: 'PAM',
        instruction: 'Enter your credentials',
        lang: 'en',
        prompts: [
          SSHUserInfoPrompt('Password: ', false),
          SSHUserInfoPrompt('Token: ', true),
        ],
      );
      final decoded =
          SSH_Message_Userauth_InfoRequest.decode(original.encode());

      expect(SSHMessage.readMessageId(original.encode()), 60);
      expect(decoded.name, 'PAM');
      expect(decoded.instruction, 'Enter your credentials');
      expect(decoded.prompts, hasLength(2));
      expect(decoded.prompts[0].promptText, 'Password: ');
      expect(decoded.prompts[0].echo, isFalse);
      expect(decoded.prompts[1].echo, isTrue);
      expect(decoded.toString(), contains('PAM'));
    });

    test('round-trips with no prompts', () {
      final original = SSH_Message_Userauth_InfoRequest(
        name: '',
        instruction: '',
        lang: '',
        prompts: const [],
      );

      expect(
        SSH_Message_Userauth_InfoRequest.decode(original.encode()).prompts,
        isEmpty,
      );
    });
  });

  group('SSH_Message_Userauth_InfoResponse', () {
    test('round-trips', () {
      final original = SSH_Message_Userauth_InfoResponse(
        responses: const ['first', 'second'],
      );
      final decoded =
          SSH_Message_Userauth_InfoResponse.decode(original.encode());

      expect(SSHMessage.readMessageId(original.encode()), 61);
      expect(decoded.responses, ['first', 'second']);
    });

    test('round-trips with no responses', () {
      final original = SSH_Message_Userauth_InfoResponse(responses: const []);

      expect(
        SSH_Message_Userauth_InfoResponse.decode(original.encode()).responses,
        isEmpty,
      );
    });
  });
}
