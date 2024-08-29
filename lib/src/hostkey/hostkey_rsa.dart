import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dartssh2/src/ssh_hostkey.dart';
import 'package:dartssh2/src/ssh_message.dart';

import 'package:pinenacl/ed25519.dart';
import 'package:pointycastle/api.dart' hide Signature;
import 'package:pointycastle/asymmetric/api.dart' as asymmetric;
import 'package:pointycastle/digests/sha1.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/random/fortuna_random.dart';
import 'package:pointycastle/signers/rsa_signer.dart';

class SSHRsaPublicKey implements SSHHostKey {
  static const type = 'ssh-rsa';

  final BigInt e;

  final BigInt n;

  SSHRsaPublicKey(this.e, this.n);

  factory SSHRsaPublicKey.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    final type = reader.readUtf8();
    if (type != SSHRsaPublicKey.type) {
      throw Exception('Invalid key type: $type');
    }
    final e = reader.readMpint();
    final n = reader.readMpint();
    return SSHRsaPublicKey(e, n);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUtf8(type);
    writer.writeMpint(e);
    writer.writeMpint(n);
    return writer.takeBytes();
  }

  bool verify(Uint8List message, SSHRsaSignature signature) {
    late RSASigner signer;

    switch (signature.type) {
      case SSHRsaSignatureType.sha1:
        signer = RSASigner(SHA1Digest(), '06052b0e03021a');
        break;
      case SSHRsaSignatureType.sha256:
        signer = RSASigner(SHA256Digest(), '0609608648016503040201');
        break;
      case SSHRsaSignatureType.sha512:
        signer = RSASigner(SHA512Digest(), '0609608648016503040203');
        break;
      default:
        throw FormatException('Unknown signature type: ${signature.type}');
    }

    signer.init(
      false,
      ParametersWithRandom(
        PublicKeyParameter<asymmetric.RSAPublicKey>(
          asymmetric.RSAPublicKey(n, e),
        ),
        FortunaRandom(),
      ),
    );

    return signer.verifySignature(
      message,
      asymmetric.RSASignature(signature.signature),
    );
  }

  @override
  String toString() {
    return 'SSHRsaKey($type, n: $n, e: $e)';
  }
}

abstract class SSHRsaSignatureType {
  static const sha1 = 'ssh-rsa';
  static const sha256 = 'rsa-sha2-256';
  static const sha512 = 'rsa-sha2-512';
}

class SSHRsaSignature implements SSHSignature {
  final String type;

  final Uint8List signature;

  SSHRsaSignature(this.type, this.signature);

  factory SSHRsaSignature.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    final type = reader.readUtf8();
    final signature = reader.readString();
    return SSHRsaSignature(type, signature);
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
    return 'SSHRsaSignature(${hex.encode(signature)})';
  }
}
