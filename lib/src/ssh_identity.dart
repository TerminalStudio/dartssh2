import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/src/ssh_hostkey.dart';
import 'package:dartssh2/src/ssh_key_pair.dart';

/// Represents an identity capable of authenticating an SSH session.
///
/// An [SSHIdentity] provides a public key representation and the capability to
/// sign challenge data, either synchronously (e.g., in-memory [SSHKeyPair]) or
/// asynchronously (e.g., external signers, OS SSH agents, hardware tokens,
/// smart cards, or secure enclaves).
abstract class SSHIdentity {
  /// Base constructor for custom [SSHIdentity] implementations.
  SSHIdentity();

  /// The signature/public-key algorithm name used for authentication (e.g.
  /// `ssh-ed25519`, `rsa-sha2-256`, `ecdsa-sha2-nistp256`).
  ///
  /// This can differ from the type encoded in [toPublicKey]. For example, an
  /// RSA identity may use `rsa-sha2-256` here while its key blob starts with
  /// `ssh-rsa` (RFC 8332).
  String get type;

  /// Optional comment or human-readable label associated with this identity
  /// (e.g., key comment or hardware token identifier).
  String? get comment => null;

  /// Whether the client should send an unsigned public key probe packet
  /// (`SSH_MSG_USERAUTH_REQUEST` with `has_signature = false`) to check if the
  /// server accepts this key before requesting a signature (RFC 4252 §7.8).
  ///
  /// Defaults to `false` for in-memory keys to avoid an extra network roundtrip.
  /// Recommended to set to `true` for external signers, hardware tokens, or OS
  /// agents to prevent unnecessary user interaction or PIN prompts for keys the
  /// server would reject.
  bool get shouldProbe => false;

  /// Returns the public key representation of this identity.
  SSHHostKey toPublicKey();

  /// Signs [data] with the private key or external signer.
  ///
  /// Can return [SSHSignature] directly (synchronously) or a
  /// `Future<SSHSignature>` (asynchronously).
  FutureOr<SSHSignature> sign(Uint8List data);

  /// Creates a custom [SSHIdentity] with the given [type], [publicKey], and
  /// [signer] function.
  ///
  /// If [shouldProbe] is `true`, the SSH client will send a public-key query
  /// packet first before calling [signer].
  factory SSHIdentity.custom({
    required String type,
    required SSHHostKey publicKey,
    required FutureOr<SSHSignature> Function(Uint8List data) signer,
    String? comment,
    bool shouldProbe,
  }) = _CustomSSHIdentity;
}

class _CustomSSHIdentity implements SSHIdentity {
  _CustomSSHIdentity({
    required this.type,
    required this.publicKey,
    required this.signer,
    this.comment,
    this.shouldProbe = false,
  });

  @override
  final String type;

  final SSHHostKey publicKey;

  final FutureOr<SSHSignature> Function(Uint8List data) signer;

  @override
  final String? comment;

  @override
  final bool shouldProbe;

  @override
  SSHHostKey toPublicKey() => publicKey;

  @override
  FutureOr<SSHSignature> sign(Uint8List data) => signer(data);
}
