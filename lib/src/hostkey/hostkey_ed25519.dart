import 'package:convert/convert.dart';
import 'package:dartssh3/src/ssh_hostkey.dart';
import 'package:dartssh3/src/ssh_message.dart';
import 'package:pinenacl/ed25519.dart';

class SSHEd25519PublicKey implements SSHHostKey {
  static const type = 'ssh-ed25519';

  final Uint8List key;

  SSHEd25519PublicKey(this.key);

  factory SSHEd25519PublicKey.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    final type = reader.readUtf8();
    if (type != SSHEd25519PublicKey.type) {
      throw Exception('Invalid key type: $type');
    }
    final key = reader.readString();
    return SSHEd25519PublicKey(key);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUtf8(type);
    writer.writeString(key);
    return writer.takeBytes();
  }

  /// Verifies Ed25519 [signature] on [message] with private key matching [publicKey].
  bool verify(Uint8List message, SSHEd25519Signature signature) {
    // tweetnacl.Signature(publicKey.key!, null).detached_verify(message, signature.sig!);
    return VerifyKey(key).verify(
      signature: Signature(signature.signature),
      message: message,
    );
  }

  @override
  String toString() {
    return 'SSHEd25519Key(${hex.encode(key)})';
  }
}

class SSHEd25519Signature implements SSHSignature {
  static const type = 'ssh-ed25519';

  final Uint8List signature;

  SSHEd25519Signature(this.signature);

  factory SSHEd25519Signature.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    final type = reader.readUtf8();
    if (type != SSHEd25519Signature.type) {
      throw Exception('Invalid signature type: $type');
    }
    final signature = reader.readString();
    return SSHEd25519Signature(signature);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUtf8(type);
    writer.writeString(signature);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSHEd25519Signature(${hex.encode(signature)})';
  }
}
