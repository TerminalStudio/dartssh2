import 'package:dartssh2/src/ssh_userauth.dart';

/// Selects the authentication methods that may productively continue.
///
/// [serverMethods] is an allow-list, not a preference list. The returned order
/// therefore follows [preferredMethods], matching OpenSSH's handling of
/// `PreferredAuthentications`.
List<SSHAuthMethod> selectContinuableAuthMethods({
  required Iterable<SSHAuthMethod> preferredMethods,
  required Iterable<String> serverMethods,
  required Set<SSHAuthMethod> availableMethods,
  void Function(String message)? onNote,
}) {
  final supportedNames = <String>{};

  for (final name in serverMethods) {
    final method = _methodFromName(name);
    if (method == null) {
      onNote?.call('Unknown authentication method from server: $name');
      continue;
    }
    if (method == SSHAuthMethod.none) {
      onNote?.call('Server listed "none" as a continuable auth method');
      continue;
    }
    supportedNames.add(name);
  }

  return [
    for (final method in preferredMethods)
      if (availableMethods.contains(method) &&
          supportedNames.contains(method.name))
        method,
  ];
}

SSHAuthMethod? _methodFromName(String name) {
  for (final method in SSHAuthMethod.values) {
    if (method.name == name) return method;
  }
  return null;
}
