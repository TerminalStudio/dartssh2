import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dartssh2/src/ssh_hostkey.dart';
import 'package:dartssh2/src/ssh_message.dart';
import 'package:pointycastle/export.dart';

class SSHEcdsaPublicKey implements SSHHostKey {
  final String type;

  final String curveId;

  final Uint8List q;

  SSHEcdsaPublicKey({
    required this.type,
    required this.curveId,
    required this.q,
  });

  factory SSHEcdsaPublicKey.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    final type = reader.readUtf8();
    if (!type.startsWith('ecdsa-sha2-')) {
      throw Exception('Invalid key type: $type');
    }
    final curveId = reader.readUtf8();
    final q = reader.readString();
    return SSHEcdsaPublicKey(type: type, curveId: curveId, q: q);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUtf8(type);
    writer.writeUtf8(curveId);
    writer.writeString(q);
    return writer.takeBytes();
  }

  bool verify(
    Uint8List message,
    SSHEcdsaSignature signature,
  ) {
    final signer = ECDSASigner(curveHash);

    signer.init(
      false,
      PublicKeyParameter(
        ECPublicKey(curve.curve.decodePoint(q), curve),
      ),
    );

    return signer.verifySignature(
      message,
      ECSignature(signature.r, signature.s),
    );
  }

  ECDomainParameters get curve {
    switch (curveId) {
      case 'nistp256':
        return ECCurve_secp256r1();
      case 'nistp384':
        return ECCurve_secp384r1();
      case 'nistp521':
        return ECCurve_secp521r1();
      default:
        throw Exception('Unsupported curve: $curveId');
    }
  }

  Digest get curveHash {
    switch (curveId) {
      case 'nistp256':
        return SHA256Digest();
      case 'nistp384':
        return SHA384Digest();
      case 'nistp521':
        return SHA512Digest();
      default:
        throw Exception('Unsupported curve: $curveId');
    }
  }

  @override
  String toString() {
    return 'SSHEcdsaKey(type: $type, curveId: $curveId, q: ${hex.encode(q)})';
  }
}

class SSHEcdsaSignature implements SSHSignature {
  final String type;

  final BigInt r;

  final BigInt s;

  SSHEcdsaSignature(this.type, this.r, this.s);

  factory SSHEcdsaSignature.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    final type = reader.readUtf8();
    if (!type.startsWith('ecdsa-sha2-')) {
      throw FormatException('Invalid signature type: $type');
    }
    final blobReader = SSHMessageReader(reader.readString());
    final r = blobReader.readMpint();
    final s = blobReader.readMpint();
    return SSHEcdsaSignature(type, r, s);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUtf8(type);
    final blobWriter = SSHMessageWriter();
    blobWriter.writeMpint(r);
    blobWriter.writeMpint(s);
    writer.writeString(blobWriter.takeBytes());
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSHEcdsaSignature($type)';
  }
}
