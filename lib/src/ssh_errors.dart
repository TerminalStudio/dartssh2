/// Interface for all the exceptions thrown by the library.
abstract class SSHError {}

/// Errors with a message.
mixin SSHMessageError {
  String get message;

  @override
  String toString() {
    return '$runtimeType($message)';
  }
}

/// Errors that are not expected to occur. Most of the time, these are caused
/// by bugs in the library.
class SSHInternalError implements SSHError {
  final Object error;

  SSHInternalError(this.error);

  @override
  String toString() {
    return '$runtimeType($error)';
  }
}

/// Errors that happen when the library fails to connect to handshake.
class SSHHandshakeError with SSHMessageError implements SSHError {
  @override
  final String message;

  SSHHandshakeError(this.message);
}

/// Errors that happen when the library fails to authenticate.
abstract class SSHAuthError with SSHMessageError implements SSHError {}

/// Errors that happen when the library tried all the authentication methods
/// and failed to authenticate.
class SSHAuthFailError with SSHMessageError implements SSHAuthError {
  @override
  final String message;

  SSHAuthFailError(this.message);
}

/// Errors that happen when the authentication failed due to other reasons.
/// For example network errors.
class SSHAuthAbortError with SSHMessageError implements SSHAuthError {
  @override
  final String message;

  SSHAuthAbortError(this.message);
}

/// Errors that happen when the library receives an malformed packet.
class SSHPacketError with SSHMessageError implements SSHError {
  @override
  final String message;

  SSHPacketError(this.message);
}

/// Errors that happen when the library receives an unexpected packet.
class SSHStateError with SSHMessageError implements SSHError {
  @override
  final String message;

  SSHStateError(this.message);
}

/// Errors that happen when the library fails to decode a key.
class SSHKeyDecodeError with SSHMessageError implements SSHError {
  @override
  final String message;

  final Object? error;

  SSHKeyDecodeError(this.message, [this.error]);

  @override
  String toString() {
    return '$runtimeType($message, $error)';
  }
}

/// Errors that happen when the library fails to decrypt the host key.
class SSHKeyDecryptError extends SSHKeyDecodeError {
  SSHKeyDecryptError(String message, [Object? error]) : super(message, error);
}

/// Errors that happen when the library fails to open a channel.
class SSHChannelOpenError implements SSHError {
  final int code;

  final String description;

  SSHChannelOpenError(this.code, this.description);

  @override
  String toString() {
    return '$runtimeType($code: $description)';
  }
}

/// Errors that happen when the library fails to send a channel request.
class SSHChannelRequestError with SSHMessageError implements SSHError {
  @override
  final String message;

  SSHChannelRequestError(this.message);
}

/// Errors that happen when the library fails to verify the host key.
class SSHHostkeyError with SSHMessageError implements SSHError {
  @override
  final String message;

  SSHHostkeyError(this.message);
}

/// Errors related to the underlying socket.
class SSHSocketError implements SSHError {
  final Object error;

  SSHSocketError(this.error);

  @override
  String toString() {
    return 'SSHSocketError($error)';
  }
}
