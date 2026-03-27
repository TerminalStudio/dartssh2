import 'dart:async';
import 'dart:mirrors';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/message/msg_kex.dart';
import 'package:dartssh2/src/ssh_packet.dart';
import 'package:test/test.dart';

void main() {
  final transportLibrary = reflectClass(SSHTransport).owner as LibraryMirror;
  final packetLibrary = reflectClass(SSHPacketSN).owner as LibraryMirror;
  Symbol privateSymbol(String name) =>
      MirrorSystem.getSymbol(name, transportLibrary);
  Symbol packetPrivateSymbol(String name) =>
      MirrorSystem.getSymbol(name, packetLibrary);
  void setPrivate(SSHTransport transport, String field, Object? value) {
    reflect(transport).setField(privateSymbol(field), value);
  }

  T getPrivate<T>(SSHTransport transport, String field) {
    return reflect(transport).getField(privateSymbol(field)).reflectee as T;
  }

  void setSequenceValue(SSHTransport transport, String field, int value) {
    final sequence =
        reflect(transport).getField(privateSymbol(field)).reflectee;
    reflect(sequence).setField(packetPrivateSymbol('_value'), value);
  }

  group('SSHTransport AEAD', () {
    test('exchanges packets with AES-GCM', () async {
      final key = Uint8List(16);
      final iv = Uint8List(12);
      for (var i = 0; i < key.length; i++) {
        key[i] = i;
      }
      for (var i = 0; i < iv.length; i++) {
        iv[i] = i + 16;
      }

      final senderSocket = _CaptureSSHSocket();
      final sender = SSHTransport(
        senderSocket,
        algorithms: const SSHAlgorithms(
          cipher: [SSHCipherType.aes128gcm],
        ),
      );

      setPrivate(sender, '_clientCipherType', SSHCipherType.aes128gcm);
      setPrivate(sender, '_localCipherKey', key);
      setPrivate(sender, '_localIV', iv);
      setPrivate(sender, '_kexInProgress', false);
      setSequenceValue(sender, '_localPacketSN', 0);

      final payload = Uint8List.fromList([250, 1, 2, 3, 4, 5]);
      sender.sendPacket(payload);

      final encryptedPacket = senderSocket.packets.last;

      final receiverSocket = _CaptureSSHSocket();
      final receivedPacket = Completer<Uint8List>();
      final receiver = SSHTransport(
        receiverSocket,
        algorithms: const SSHAlgorithms(
          cipher: [SSHCipherType.aes128gcm],
        ),
        onPacket: (packet) {
          if (!receivedPacket.isCompleted) {
            receivedPacket.complete(packet);
          }
        },
      );

      setPrivate(receiver, '_remoteVersion', 'SSH-2.0-test');
      setPrivate(receiver, '_serverCipherType', SSHCipherType.aes128gcm);
      setPrivate(receiver, '_remoteCipherKey', key);
      setPrivate(receiver, '_remoteIV', iv);
      setSequenceValue(receiver, '_remotePacketSN', 0);

      receiverSocket.addIncomingBytes(encryptedPacket);

      final received =
          await receivedPacket.future.timeout(const Duration(seconds: 2));
      expect(received, payload);

      sender.close();
      receiver.close();
    });

    test('reports AEAD authentication failure when packet is tampered',
        () async {
      final key = Uint8List(16);
      final iv = Uint8List(12);
      for (var i = 0; i < key.length; i++) {
        key[i] = i;
      }
      for (var i = 0; i < iv.length; i++) {
        iv[i] = i + 16;
      }

      final senderSocket = _CaptureSSHSocket();
      final sender = SSHTransport(
        senderSocket,
        algorithms: const SSHAlgorithms(
          cipher: [SSHCipherType.aes128gcm],
        ),
      );

      setPrivate(sender, '_clientCipherType', SSHCipherType.aes128gcm);
      setPrivate(sender, '_localCipherKey', key);
      setPrivate(sender, '_localIV', iv);
      setPrivate(sender, '_kexInProgress', false);
      setSequenceValue(sender, '_localPacketSN', 0);

      sender.sendPacket(Uint8List.fromList([251, 9, 8, 7]));
      final tampered = Uint8List.fromList(senderSocket.packets.last);
      tampered[tampered.length - 1] ^= 0x01;

      final receiverSocket = _CaptureSSHSocket();
      final receiver = SSHTransport(
        receiverSocket,
        algorithms: const SSHAlgorithms(
          cipher: [SSHCipherType.aes128gcm],
        ),
      );

      setPrivate(receiver, '_remoteVersion', 'SSH-2.0-test');
      setPrivate(receiver, '_serverCipherType', SSHCipherType.aes128gcm);
      setPrivate(receiver, '_remoteCipherKey', key);
      setPrivate(receiver, '_remoteIV', iv);
      setSequenceValue(receiver, '_remotePacketSN', 0);

      receiverSocket.addIncomingBytes(tampered);

      await expectLater(
        receiver.done,
        throwsA(
          predicate(
            (error) =>
                error is SSHPacketError &&
                error.toString().contains('AEAD authentication failed'),
          ),
        ),
      );

      sender.close();
      receiver.close();
    });

    test('validates AEAD nonce IV length', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      expect(
        () => reflect(transport).invoke(
          privateSymbol('_nonceForSequence'),
          [Uint8List(8), 0],
        ),
        throwsA(isA<ArgumentError>()),
      );

      transport.close();
    });

    test('consumeAeadPacket returns null for incomplete inputs', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      setPrivate(transport, '_remoteVersion', 'SSH-2.0-test');
      setPrivate(transport, '_serverCipherType', SSHCipherType.aes128gcm);
      setPrivate(transport, '_remoteCipherKey', Uint8List(16));
      setPrivate(transport, '_remoteIV', Uint8List(12));
      setSequenceValue(transport, '_remotePacketSN', 0);

      final resultNoHeader = reflect(transport).invoke(
          privateSymbol('_consumeAeadPacket'),
          [SSHCipherType.aes128gcm]).reflectee;
      expect(resultNoHeader, isNull);

      final dynamic buffer = getPrivate<dynamic>(transport, '_buffer');
      buffer.add(Uint8List.fromList([0, 0, 0, 20, 1, 2, 3]));

      final resultPartial = reflect(transport).invoke(
          privateSymbol('_consumeAeadPacket'),
          [SSHCipherType.aes128gcm]).reflectee;
      expect(resultPartial, isNull);

      transport.close();
    });

    test('applyLocalKeys keeps AEAD mode without cipher/mac instances', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      setPrivate(transport, '_kexType', SSHKexType.x25519);
      setPrivate(transport, '_sharedSecret', BigInt.from(1));
      setPrivate(transport, '_exchangeHash',
          Uint8List.fromList(List<int>.filled(32, 1)));
      setPrivate(
          transport, '_sessionId', Uint8List.fromList(List<int>.filled(32, 2)));
      setPrivate(transport, '_clientCipherType', SSHCipherType.aes128gcm);

      reflect(transport).invoke(privateSymbol('_applyLocalKeys'), const []);

      final localKey = getPrivate<Uint8List?>(transport, '_localCipherKey');
      final localIv = getPrivate<Uint8List?>(transport, '_localIV');
      expect(localKey, isNotNull);
      expect(localKey!.length, SSHCipherType.aes128gcm.keySize);
      expect(localIv, isNotNull);
      expect(localIv!.length, SSHCipherType.aes128gcm.ivSize);
      expect(getPrivate<Object?>(transport, '_encryptCipher'), isNull);
      expect(getPrivate<Object?>(transport, '_localMac'), isNull);

      transport.close();
    });

    test('applyRemoteKeys keeps AEAD mode without cipher/mac instances', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      setPrivate(transport, '_kexType', SSHKexType.x25519);
      setPrivate(transport, '_sharedSecret', BigInt.from(1));
      setPrivate(transport, '_exchangeHash',
          Uint8List.fromList(List<int>.filled(32, 3)));
      setPrivate(
          transport, '_sessionId', Uint8List.fromList(List<int>.filled(32, 4)));
      setPrivate(transport, '_serverCipherType', SSHCipherType.aes128gcm);

      reflect(transport).invoke(privateSymbol('_applyRemoteKeys'), const []);

      final remoteKey = getPrivate<Uint8List?>(transport, '_remoteCipherKey');
      final remoteIv = getPrivate<Uint8List?>(transport, '_remoteIV');
      expect(remoteKey, isNotNull);
      expect(remoteKey!.length, SSHCipherType.aes128gcm.keySize);
      expect(remoteIv, isNotNull);
      expect(remoteIv!.length, SSHCipherType.aes128gcm.ivSize);
      expect(getPrivate<Object?>(transport, '_decryptCipher'), isNull);
      expect(getPrivate<Object?>(transport, '_remoteMac'), isNull);

      transport.close();
    });

    test('applyLocalKeys creates cipher and mac for non-AEAD algorithms', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      setPrivate(transport, '_kexType', SSHKexType.x25519);
      setPrivate(transport, '_sharedSecret', BigInt.from(5));
      setPrivate(transport, '_exchangeHash',
          Uint8List.fromList(List<int>.filled(32, 6)));
      setPrivate(
          transport, '_sessionId', Uint8List.fromList(List<int>.filled(32, 7)));
      setPrivate(transport, '_clientCipherType', SSHCipherType.aes128ctr);
      setPrivate(transport, '_clientMacType', SSHMacType.hmacSha256);

      reflect(transport).invoke(privateSymbol('_applyLocalKeys'), const []);

      expect(getPrivate<Object?>(transport, '_encryptCipher'), isNotNull);
      expect(getPrivate<Object?>(transport, '_localMac'), isNotNull);

      transport.close();
    });

    test('applyRemoteKeys creates cipher and mac for non-AEAD algorithms', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      setPrivate(transport, '_kexType', SSHKexType.x25519);
      setPrivate(transport, '_sharedSecret', BigInt.from(8));
      setPrivate(transport, '_exchangeHash',
          Uint8List.fromList(List<int>.filled(32, 9)));
      setPrivate(transport, '_sessionId',
          Uint8List.fromList(List<int>.filled(32, 10)));
      setPrivate(transport, '_serverCipherType', SSHCipherType.aes128ctr);
      setPrivate(transport, '_serverMacType', SSHMacType.hmacSha256);

      reflect(transport).invoke(privateSymbol('_applyRemoteKeys'), const []);

      expect(getPrivate<Object?>(transport, '_decryptCipher'), isNotNull);
      expect(getPrivate<Object?>(transport, '_remoteMac'), isNotNull);

      transport.close();
    });

    test('kexinit allows missing MAC when AEAD cipher is selected', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(
        socket,
        algorithms: const SSHAlgorithms(
          cipher: [SSHCipherType.aes128gcm],
          mac: [SSHMacType.hmacSha256],
        ),
      );

      setPrivate(transport, '_kexInProgress', true);
      setPrivate(transport, '_sentKexInit', true);

      final payload = SSH_Message_KexInit(
        kexAlgorithms: [SSHKexType.x25519.name],
        serverHostKeyAlgorithms: [SSHHostkeyType.ed25519.name],
        encryptionClientToServer: [SSHCipherType.aes128gcm.name],
        encryptionServerToClient: [SSHCipherType.aes128gcm.name],
        macClientToServer: const ['missing-mac'],
        macServerToClient: const ['missing-mac'],
        compressionClientToServer: const ['none'],
        compressionServerToClient: const ['none'],
        firstKexPacketFollows: false,
      ).encode();

      expect(
        () => reflect(transport)
            .invoke(privateSymbol('_handleMessageKexInit'), [payload]),
        returnsNormally,
      );

      transport.close();
    });

    test('sendPacket buffers non-kex packets during key exchange', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      setPrivate(transport, '_kexInProgress', true);

      // 94 is outside control/kex message ranges and should be buffered.
      transport.sendPacket(Uint8List.fromList([94, 1, 2]));

      final pending =
          getPrivate<List<Uint8List>>(transport, '_rekeyPendingPackets');
      expect(pending, hasLength(1));
      expect(pending.first, Uint8List.fromList([94, 1, 2]));

      transport.close();
    });

    test('applyLocalKeys throws when cipher type is missing', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      expect(
        () => reflect(transport)
            .invoke(privateSymbol('_applyLocalKeys'), const []),
        throwsA(isA<StateError>()),
      );

      transport.close();
    });

    test('applyRemoteKeys throws when cipher type is missing', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      expect(
        () => reflect(transport)
            .invoke(privateSymbol('_applyRemoteKeys'), const []),
        throwsA(isA<StateError>()),
      );

      transport.close();
    });

    test('applyLocalKeys throws when non-AEAD MAC type is missing', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      setPrivate(transport, '_kexType', SSHKexType.x25519);
      setPrivate(transport, '_sharedSecret', BigInt.from(11));
      setPrivate(transport, '_exchangeHash',
          Uint8List.fromList(List<int>.filled(32, 12)));
      setPrivate(transport, '_sessionId',
          Uint8List.fromList(List<int>.filled(32, 13)));
      setPrivate(transport, '_clientCipherType', SSHCipherType.aes128ctr);

      expect(
        () => reflect(transport)
            .invoke(privateSymbol('_applyLocalKeys'), const []),
        throwsA(isA<StateError>()),
      );

      transport.close();
    });

    test('applyRemoteKeys throws when non-AEAD MAC type is missing', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      setPrivate(transport, '_kexType', SSHKexType.x25519);
      setPrivate(transport, '_sharedSecret', BigInt.from(14));
      setPrivate(transport, '_exchangeHash',
          Uint8List.fromList(List<int>.filled(32, 15)));
      setPrivate(transport, '_sessionId',
          Uint8List.fromList(List<int>.filled(32, 16)));
      setPrivate(transport, '_serverCipherType', SSHCipherType.aes128ctr);

      expect(
        () => reflect(transport)
            .invoke(privateSymbol('_applyRemoteKeys'), const []),
        throwsA(isA<StateError>()),
      );

      transport.close();
    });

    test('kexinit requires client MAC when non-AEAD cipher is selected', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(
        socket,
        algorithms: const SSHAlgorithms(
          cipher: [SSHCipherType.aes128ctr],
          mac: [SSHMacType.hmacSha256],
        ),
      );

      setPrivate(transport, '_kexInProgress', true);
      setPrivate(transport, '_sentKexInit', true);

      final payload = SSH_Message_KexInit(
        kexAlgorithms: [SSHKexType.x25519.name],
        serverHostKeyAlgorithms: [SSHHostkeyType.ed25519.name],
        encryptionClientToServer: [SSHCipherType.aes128ctr.name],
        encryptionServerToClient: [SSHCipherType.aes128ctr.name],
        macClientToServer: const ['missing-mac'],
        macServerToClient: [SSHMacType.hmacSha256.name],
        compressionClientToServer: const ['none'],
        compressionServerToClient: const ['none'],
        firstKexPacketFollows: false,
      ).encode();

      expect(
        () => reflect(transport)
            .invoke(privateSymbol('_handleMessageKexInit'), [payload]),
        throwsA(isA<StateError>()),
      );

      transport.close();
    });

    test('kexinit requires server MAC when non-AEAD cipher is selected', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(
        socket,
        algorithms: const SSHAlgorithms(
          cipher: [SSHCipherType.aes128ctr],
          mac: [SSHMacType.hmacSha256],
        ),
      );

      setPrivate(transport, '_kexInProgress', true);
      setPrivate(transport, '_sentKexInit', true);

      final payload = SSH_Message_KexInit(
        kexAlgorithms: [SSHKexType.x25519.name],
        serverHostKeyAlgorithms: [SSHHostkeyType.ed25519.name],
        encryptionClientToServer: [SSHCipherType.aes128ctr.name],
        encryptionServerToClient: [SSHCipherType.aes128ctr.name],
        macClientToServer: [SSHMacType.hmacSha256.name],
        macServerToClient: const ['missing-mac'],
        compressionClientToServer: const ['none'],
        compressionServerToClient: const ['none'],
        firstKexPacketFollows: false,
      ).encode();

      expect(
        () => reflect(transport)
            .invoke(privateSymbol('_handleMessageKexInit'), [payload]),
        throwsA(isA<StateError>()),
      );

      transport.close();
    });
  });
}

class _CaptureSSHSocket implements SSHSocket {
  final _inputController = StreamController<Uint8List>();
  final _doneCompleter = Completer<void>();
  final packets = <Uint8List>[];

  @override
  Stream<Uint8List> get stream => _inputController.stream;

  @override
  StreamSink<List<int>> get sink => _CaptureSink(packets);

  @override
  Future<void> get done => _doneCompleter.future;

  void addIncomingBytes(Uint8List data) {
    _inputController.add(Uint8List.fromList(data));
  }

  @override
  Future<void> close() async {
    if (!_doneCompleter.isCompleted) {
      _doneCompleter.complete();
    }
    await _inputController.close();
  }

  @override
  void destroy() {
    if (!_doneCompleter.isCompleted) {
      _doneCompleter.complete();
    }
    unawaited(_inputController.close());
  }
}

class _CaptureSink implements StreamSink<List<int>> {
  _CaptureSink(this._packets);

  final List<Uint8List> _packets;

  @override
  void add(List<int> data) {
    _packets.add(Uint8List.fromList(data));
  }

  @override
  Future<void> addStream(Stream<List<int>> stream) async {
    await for (final chunk in stream) {
      add(chunk);
    }
  }

  @override
  void addError(Object error, [StackTrace? stackTrace]) {}

  @override
  Future<void> close() async {}

  @override
  Future<void> get done async {}
}
