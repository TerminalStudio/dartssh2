// ignore_for_file: camel_case_types

import 'dart:typed_data';

import 'package:dartssh3/src/ssh_message.dart';
import 'package:dartssh3/src/ssh_userauth.dart';

class SSH_Message_Userauth_Request extends SSHMessage {
  static const messageId = 50;

  final String user;
  final String serviceName;
  final String methodName;

  /* 'password' method specific fields */

  final String? oldPassword;
  final String? password;

  /* 'publickey' method specific fields */

  final String? publicKeyAlgorithm;
  final Uint8List? publicKey;
  final Uint8List? signature;

  /* 'publickey' method specific fields */

  final String? languageTag;
  final String? submethods;

  SSH_Message_Userauth_Request({
    required this.user,
    required this.serviceName,
    required this.methodName,
    this.oldPassword,
    this.password,
    this.publicKeyAlgorithm,
    this.publicKey,
    this.signature,
    this.languageTag,
    this.submethods,
  });

  factory SSH_Message_Userauth_Request.password({
    required String user,
    required String password,
    String serviceName = 'ssh-connection',
  }) {
    return SSH_Message_Userauth_Request(
      serviceName: serviceName,
      user: user,
      password: password,
      methodName: 'password',
    );
  }

  factory SSH_Message_Userauth_Request.newPassword({
    required String user,
    required String oldPassword,
    required String newPassword,
    String serviceName = 'ssh-connection',
  }) {
    return SSH_Message_Userauth_Request(
      serviceName: serviceName,
      user: user,
      oldPassword: oldPassword,
      password: newPassword,
      methodName: 'password',
    );
  }

  factory SSH_Message_Userauth_Request.publicKey({
    required String username,
    required String publicKeyAlgorithm,
    required Uint8List publicKey,
    required Uint8List? signature,
    String serviceName = 'ssh-connection',
  }) {
    return SSH_Message_Userauth_Request(
      serviceName: serviceName,
      user: username,
      publicKeyAlgorithm: publicKeyAlgorithm,
      publicKey: publicKey,
      signature: signature,
      methodName: 'publickey',
    );
  }

  factory SSH_Message_Userauth_Request.keyboardInteractive({
    required String user,
    String languageTag = '',
    String submethods = '',
    String serviceName = 'ssh-connection',
  }) {
    return SSH_Message_Userauth_Request(
      serviceName: serviceName,
      user: user,
      languageTag: languageTag,
      submethods: submethods,
      methodName: 'keyboard-interactive',
    );
  }

  factory SSH_Message_Userauth_Request.none({
    required String user,
    String serviceName = 'ssh-connection',
  }) {
    return SSH_Message_Userauth_Request(
      serviceName: serviceName,
      user: user,
      methodName: 'none',
    );
  }

  factory SSH_Message_Userauth_Request.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final user = reader.readUtf8();
    final serviceName = reader.readUtf8();
    final methodName = reader.readUtf8();
    switch (methodName) {
      case 'password':
        final hasNewPassword = reader.readBool();
        final password = reader.readUtf8();
        if (hasNewPassword) {
          final oldPassword = reader.readUtf8();
          return SSH_Message_Userauth_Request.newPassword(
            user: user,
            oldPassword: oldPassword,
            newPassword: password,
            serviceName: serviceName,
          );
        } else {
          return SSH_Message_Userauth_Request.password(
            user: user,
            password: password,
            serviceName: serviceName,
          );
        }
      case 'publickey':
        final publicKeyAlgorithm = reader.readUtf8();
        final publicKey = reader.readString();
        final signature = reader.readString();
        return SSH_Message_Userauth_Request.publicKey(
          username: user,
          serviceName: serviceName,
          publicKeyAlgorithm: publicKeyAlgorithm,
          publicKey: publicKey,
          signature: signature,
        );
      case 'keyboard-interactive':
        final languageTag = reader.readUtf8();
        final submethods = reader.readUtf8();
        return SSH_Message_Userauth_Request.keyboardInteractive(
          user: user,
          serviceName: serviceName,
          languageTag: languageTag,
          submethods: submethods,
        );
      case 'none':
        return SSH_Message_Userauth_Request.none(
          user: user,
          serviceName: serviceName,
        );
      default:
        throw UnimplementedError('Unrecognized method name: $methodName');
    }
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeUtf8(user);
    writer.writeUtf8(serviceName);
    writer.writeUtf8(methodName);
    switch (methodName) {
      case 'password':
        if (oldPassword != null) {
          writer.writeBool(true);
          writer.writeUtf8(oldPassword!);
          writer.writeUtf8(password!);
        } else {
          writer.writeBool(false);
          writer.writeUtf8(password!);
        }
        break;
      case 'publickey':
        writer.writeBool(signature != null);
        writer.writeUtf8(publicKeyAlgorithm!);
        writer.writeString(publicKey!);
        if (signature != null) writer.writeString(signature!);
        break;
      case 'keyboard-interactive':
        writer.writeUtf8(languageTag!);
        writer.writeUtf8(submethods!);
        break;
      case 'none':
        break;
      default:
        throw UnimplementedError('Unrecognized method name: $methodName');
    }
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_Userauth_Request(user: $user, serviceName: $serviceName, methodName: $methodName)';
  }
}

class SSH_Message_Userauth_Failure extends SSHMessage {
  static const messageId = 51;

  final List<String> methodsLeft;
  final bool partialSuccess;

  SSH_Message_Userauth_Failure({
    required this.methodsLeft,
    this.partialSuccess = false,
  });

  factory SSH_Message_Userauth_Failure.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final methodsLeft = reader.readNameList();
    final partialSuccess = reader.readBool();
    return SSH_Message_Userauth_Failure(
      methodsLeft: methodsLeft,
      partialSuccess: partialSuccess,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeNameList(methodsLeft);
    writer.writeBool(partialSuccess);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_Userauth_Failure(methodsLeft: $methodsLeft, partialSuccess: $partialSuccess)';
  }
}

class SSH_Message_Userauth_Success extends SSHMessage {
  static const messageId = 52;

  SSH_Message_Userauth_Success();

  factory SSH_Message_Userauth_Success.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    return SSH_Message_Userauth_Success();
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_Userauth_Success()';
  }
}

class SSH_Message_Userauth_Banner extends SSHMessage {
  static const messageId = 53;

  final String message;
  final String language;

  SSH_Message_Userauth_Banner({
    required this.message,
    this.language = '',
  });

  factory SSH_Message_Userauth_Banner.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final message = reader.readUtf8();
    final language = reader.readUtf8();
    return SSH_Message_Userauth_Banner(
      message: message,
      language: language,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeUtf8(message);
    writer.writeUtf8(language);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_Userauth_Banner(message: $message, language: $language)';
  }
}

class SSH_Message_Userauth_Passwd_ChangeReq extends SSHMessage {
  static const messageId = 60;

  final String prompt;

  SSH_Message_Userauth_Passwd_ChangeReq({
    required this.prompt,
  });

  factory SSH_Message_Userauth_Passwd_ChangeReq.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final prompt = reader.readUtf8();
    return SSH_Message_Userauth_Passwd_ChangeReq(
      prompt: prompt,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeUtf8(prompt);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_Userauth_Password_Change_Request(prompt: $prompt)';
  }
}

class SSH_Message_Userauth_InfoRequest implements SSHMessage {
  static const messageId = 60;

  final String name;
  final String instruction;
  final String lang;
  final List<SSHUserInfoPrompt> prompts;

  SSH_Message_Userauth_InfoRequest({
    required this.name,
    required this.instruction,
    required this.lang,
    required this.prompts,
  });

  factory SSH_Message_Userauth_InfoRequest.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final name = reader.readUtf8();
    final instruction = reader.readUtf8();
    final lang = reader.readUtf8();

    final prompts = <SSHUserInfoPrompt>[];
    final promptCount = reader.readUint32();
    for (var i = 0; i < promptCount; i++) {
      final prompt = reader.readUtf8();
      final echo = reader.readBool();
      prompts.add(SSHUserInfoPrompt(prompt, echo));
    }

    return SSH_Message_Userauth_InfoRequest(
      name: name,
      instruction: instruction,
      lang: lang,
      prompts: prompts,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeUtf8(name);
    writer.writeUtf8(instruction);
    writer.writeUtf8(lang);
    writer.writeUint32(prompts.length);
    for (var prompt in prompts) {
      writer.writeUtf8(prompt.promptText);
      writer.writeBool(prompt.echo);
    }
    return writer.takeBytes();
  }

  @override
  String toString() {
    return '$runtimeType(name: $name, instruction: $instruction, lang: $lang, prompts: $prompts)';
  }
}

class SSH_Message_Userauth_InfoResponse implements SSHMessage {
  static const messageId = 61;

  final List<String> responses;

  SSH_Message_Userauth_InfoResponse({
    required this.responses,
  });

  factory SSH_Message_Userauth_InfoResponse.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final responseCount = reader.readUint32();
    final responses = <String>[];
    for (var i = 0; i < responseCount; i++) {
      responses.add(reader.readUtf8());
    }
    return SSH_Message_Userauth_InfoResponse(
      responses: responses,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeUint32(responses.length);
    for (var response in responses) {
      writer.writeUtf8(response);
    }
    return writer.takeBytes();
  }

  @override
  String toString() {
    return '$runtimeType(responses: $responses)';
  }
}
