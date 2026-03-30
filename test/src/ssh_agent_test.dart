import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/hostkey/hostkey_rsa.dart';
import 'package:dartssh2/src/ssh_channel.dart';
import 'package:dartssh2/src/message/base.dart';
import 'package:test/test.dart';

import '../test_utils.dart';

class _RecordingAgentHandler implements SSHAgentHandler {
  _RecordingAgentHandler(this.response);

  final Uint8List response;
  final requests = <Uint8List>[];

  @override
  Future<Uint8List> handleRequest(Uint8List request) async {
    requests.add(request);
    return response;
  }
}

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

  test('SSHKeyPairAgent returns failure for empty and unknown requests',
      () async {
    final identity = rsaIdentity();
    final agent = SSHKeyPairAgent([identity]);

    final emptyResponse = await agent.handleRequest(Uint8List(0));
    expect(
        SSHMessageReader(emptyResponse).readUint8(), SSHAgentProtocol.failure);

    final unknownWriter = SSHMessageWriter();
    unknownWriter.writeUint8(255);
    final unknownResponse =
        await agent.handleRequest(unknownWriter.takeBytes());
    expect(
      SSHMessageReader(unknownResponse).readUint8(),
      SSHAgentProtocol.failure,
    );
  });

  test('SSHKeyPairAgent returns failure when signing with unknown identity',
      () async {
    final agent = SSHKeyPairAgent([rsaIdentity()]);
    final writer = SSHMessageWriter();
    writer.writeUint8(SSHAgentProtocol.signRequest);
    writer.writeString(Uint8List.fromList([0, 1, 2, 3]));
    writer.writeString(Uint8List.fromList('sign-me'.codeUnits));
    writer.writeUint32(SSHAgentProtocol.rsaSha2_256);

    final response = await agent.handleRequest(writer.takeBytes());

    expect(SSHMessageReader(response).readUint8(), SSHAgentProtocol.failure);
  });

  test('SSHAgentChannel handles fragmented request frames', () async {
    final sentMessages = <SSHMessage>[];
    final dataMessage = Completer<SSH_Message_Channel_Data>();
    final handler = _RecordingAgentHandler(Uint8List.fromList([42, 43, 44]));

    final controller = SSHChannelController(
      localId: 1,
      localMaximumPacketSize: 1024,
      localInitialWindowSize: 1024,
      remoteId: 2,
      remoteMaximumPacketSize: 1024,
      remoteInitialWindowSize: 1024,
      sendMessage: (message) {
        sentMessages.add(message);
        if (message is SSH_Message_Channel_Data && !dataMessage.isCompleted) {
          dataMessage.complete(message);
        }
      },
    );

    SSHAgentChannel(controller.channel, handler);

    final requestPayload = Uint8List.fromList([
      SSHAgentProtocol.requestIdentities,
    ]);
    final requestWriter = SSHMessageWriter();
    requestWriter.writeUint32(requestPayload.length);
    requestWriter.writeBytes(requestPayload);
    final framedRequest = requestWriter.takeBytes();

    controller.handleMessage(
      SSH_Message_Channel_Data(
        recipientChannel: controller.localId,
        data: framedRequest.sublist(0, 2),
      ),
    );

    controller.handleMessage(
      SSH_Message_Channel_Data(
        recipientChannel: controller.localId,
        data: framedRequest.sublist(2),
      ),
    );

    final responseMessage = await dataMessage.future;
    expect(handler.requests.length, 1);
    expect(handler.requests.single, requestPayload);

    final responseReader = SSHMessageReader(responseMessage.data);
    expect(responseReader.readUint32(), 3);
    expect(responseReader.readBytes(3), Uint8List.fromList([42, 43, 44]));

    expect(
      sentMessages.whereType<SSH_Message_Channel_Data>().length,
      1,
    );

    controller.destroy();
  });

  test('SSHAgentChannel handles back-to-back frames in one chunk', () async {
    final dataMessages = <SSH_Message_Channel_Data>[];
    final twoResponses = Completer<void>();
    final handler = _RecordingAgentHandler(Uint8List.fromList([7, 8]));

    final controller = SSHChannelController(
      localId: 1,
      localMaximumPacketSize: 1024,
      localInitialWindowSize: 1024,
      remoteId: 2,
      remoteMaximumPacketSize: 1024,
      remoteInitialWindowSize: 1024,
      sendMessage: (message) {
        if (message is SSH_Message_Channel_Data) {
          dataMessages.add(message);
          if (dataMessages.length == 2 && !twoResponses.isCompleted) {
            twoResponses.complete();
          }
        }
      },
    );

    SSHAgentChannel(controller.channel, handler);

    Uint8List frame(Uint8List payload) {
      final writer = SSHMessageWriter();
      writer.writeUint32(payload.length);
      writer.writeBytes(payload);
      return writer.takeBytes();
    }

    final requestA = Uint8List.fromList([SSHAgentProtocol.requestIdentities]);
    final requestB = Uint8List.fromList([SSHAgentProtocol.signRequest]);

    final frameA = frame(requestA);
    final frameB = frame(requestB);
    final chunk = Uint8List(frameA.length + frameB.length)
      ..setAll(0, frameA)
      ..setAll(frameA.length, frameB);

    controller.handleMessage(
      SSH_Message_Channel_Data(
        recipientChannel: controller.localId,
        data: chunk,
      ),
    );

    await twoResponses.future;

    expect(handler.requests.length, 2);
    expect(handler.requests[0], requestA);
    expect(handler.requests[1], requestB);

    for (final response in dataMessages) {
      final responseReader = SSHMessageReader(response.data);
      expect(responseReader.readUint32(), 2);
      expect(responseReader.readBytes(2), Uint8List.fromList([7, 8]));
    }

    controller.destroy();
  });

  test('SSHAgentChannel ignores incomplete frame when channel closes',
      () async {
    final dataMessages = <SSH_Message_Channel_Data>[];
    final handler = _RecordingAgentHandler(Uint8List.fromList([1]));

    final controller = SSHChannelController(
      localId: 1,
      localMaximumPacketSize: 1024,
      localInitialWindowSize: 1024,
      remoteId: 2,
      remoteMaximumPacketSize: 1024,
      remoteInitialWindowSize: 1024,
      sendMessage: (message) {
        if (message is SSH_Message_Channel_Data) {
          dataMessages.add(message);
        }
      },
    );

    SSHAgentChannel(controller.channel, handler);

    final truncatedFrame = Uint8List.fromList([
      0,
      0,
      0,
      10,
      SSHAgentProtocol.requestIdentities,
    ]);

    controller.handleMessage(
      SSH_Message_Channel_Data(
        recipientChannel: controller.localId,
        data: truncatedFrame,
      ),
    );

    controller.handleMessage(
      SSH_Message_Channel_EOF(recipientChannel: controller.localId),
    );
    controller.handleMessage(
      SSH_Message_Channel_Close(recipientChannel: controller.localId),
    );

    await Future<void>.delayed(Duration.zero);

    expect(handler.requests, isEmpty);
    expect(dataMessages, isEmpty);

    controller.destroy();
  });
}
