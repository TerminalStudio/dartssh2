import 'dart:async';
import 'dart:mirrors';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/ssh_algorithm.dart';
import 'package:dartssh2/src/ssh_errors.dart';
import 'package:dartssh2/src/ssh_packet.dart';
import 'package:dartssh2/src/ssh_transport.dart';
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
