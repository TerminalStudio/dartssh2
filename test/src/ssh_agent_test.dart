import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/hostkey/hostkey_rsa.dart';
import 'package:dartssh2/src/ssh_message.dart';
import 'package:test/test.dart';

import '../test_utils.dart';

void main() {
  final rsaPrivate = fixture('ssh-rsa/id_rsa');

  SSHKeyPair rsaIdentity() {
    return SSHKeyPair.fromPem(rsaPrivate).single;
  }

  Uint8List buildRequestIdentities() {
    final writer = SSHMessageWriter();
    writer.writeUint8(SSHAgentProtocol.requestIdentities);
    return writer.takeBytes();
  }

  Uint8List buildSignRequest(SSHKeyPair identity, Uint8List data, int flags) {
    final writer = SSHMessageWriter();
    writer.writeUint8(SSHAgentProtocol.signRequest);
    writer.writeString(identity.toPublicKey().encode());
    writer.writeString(data);
    writer.writeUint32(flags);
    return writer.takeBytes();
  }

  test('SSHKeyPairAgent returns identities', () async {
    final identity = rsaIdentity();
    final agent = SSHKeyPairAgent([identity], comment: 'test-key');

    final response = await agent.handleRequest(buildRequestIdentities());
    final reader = SSHMessageReader(response);

    expect(reader.readUint8(), SSHAgentProtocol.identitiesAnswer);
    expect(reader.readUint32(), 1);
    final keyBlob = reader.readString();
    final comment = reader.readUtf8();

    expect(keyBlob, identity.toPublicKey().encode());
    expect(comment, 'test-key');
  });

  test('SSHKeyPairAgent signs RSA with expected signature type', () async {
    final identity = rsaIdentity();
    final agent = SSHKeyPairAgent([identity]);
    final data = Uint8List.fromList('sign-me'.codeUnits);

    final cases = <int, String>{
      SSHAgentProtocol.rsaSha2_256: SSHRsaSignatureType.sha256,
      SSHAgentProtocol.rsaSha2_512: SSHRsaSignatureType.sha512,
      0: SSHRsaSignatureType.sha1,
    };

    for (final entry in cases.entries) {
      final response = await agent.handleRequest(
        buildSignRequest(identity, data, entry.key),
      );
      final reader = SSHMessageReader(response);
      expect(reader.readUint8(), SSHAgentProtocol.signResponse);

      final signatureBlob = reader.readString();
      final signature = SSHRsaSignature.decode(signatureBlob);
      expect(signature.type, entry.value);
    }
  });
}
