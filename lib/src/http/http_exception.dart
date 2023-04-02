/// Exception thrown when an SSH HTTP request fails.
class SSHHttpException implements Exception {
  final String message;
  final Uri? uri;

  const SSHHttpException(this.message, {this.uri});

  @override
  String toString() {
    var b = StringBuffer()
      ..write('SSHHttpException: ')
      ..write(message);
    var uri = this.uri;
    if (uri != null) {
      b.write(', uri = $uri');
    }
    return b.toString();
  }
}
