enum SSHAuthMethod {
  none,
  password,
  publicKey,
  keyboardInteractive,
  // hostbased,
}

extension SSHAuthMethodX on SSHAuthMethod {
  String get name {
    switch (this) {
      case SSHAuthMethod.none:
        return 'none';
      case SSHAuthMethod.password:
        return 'password';
      case SSHAuthMethod.publicKey:
        return 'publickey';
      case SSHAuthMethod.keyboardInteractive:
        return 'keyboard-interactive';
    }
  }
}

class SSHUserInfoRequest {
  SSHUserInfoRequest(this.name, this.instruction, this.prompts);

  /// Name of the request. For example, ""Password Expired".
  final String name;

  /// Instructions for the user. For example, "Please enter your password."
  final String instruction;

  /// List of prompts.
  final List<SSHUserInfoPrompt> prompts;
}

class SSHUserInfoPrompt {
  SSHUserInfoPrompt(this.promptText, this.echo);

  /// The prompt string. For example, "Password: ".
  final String promptText;

  /// Indicates whether or not the user input should be echoed as characters are typed.
  final bool echo;

  @override
  String toString() => '$runtimeType(prompt: $promptText, echo: $echo)';
}

class SSHChangePasswordResponse {
  SSHChangePasswordResponse(this.oldPassword, this.newPassword);

  /// Old password of the user.
  final String oldPassword;

  /// New password of the user.
  final String newPassword;
}
