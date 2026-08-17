import 'dart:typed_data';

import 'package:dartssh2/src/message/msg_kex_dh.dart';
import 'package:dartssh2/src/ssh_message.dart';
import 'package:test/test.dart';

void main() {
  // A value wide enough to need several bytes and to exercise the mpint sign
  // handling, which pads values whose top bit is set.
  final big = BigInt.parse('9' * 60);
  final highBit = BigInt.parse('ff112233445566778899', radix: 16);
  final hostKey = Uint8List.fromList(List.generate(48, (i) => i));
  final signature = Uint8List.fromList(List.generate(72, (i) => 255 - i));

  group('SSH_Message_KexDH_Init', () {
    test('round-trips', () {
      final original = SSH_Message_KexDH_Init(e: big);
      final decoded = SSH_Message_KexDH_Init.decode(original.encode());

      expect(decoded.e, big);
      expect(original.toString(), contains('SSH_Message_KexDH_Init'));
    });

    test('carries the right message id', () {
      final encoded = SSH_Message_KexDH_Init(e: BigInt.one).encode();

      expect(SSHMessage.readMessageId(encoded), 30);
    });

    test('preserves a value whose top bit is set', () {
      final original = SSH_Message_KexDH_Init(e: highBit);

      expect(SSH_Message_KexDH_Init.decode(original.encode()).e, highBit);
    });
  });

  group('SSH_Message_KexDH_Reply', () {
    test('round-trips', () {
      final original = SSH_Message_KexDH_Reply(
        hostPublicKey: hostKey,
        f: big,
        signature: signature,
      );
      final decoded = SSH_Message_KexDH_Reply.decode(original.encode());

      expect(decoded.hostPublicKey, hostKey);
      expect(decoded.f, big);
      expect(decoded.signature, signature);
      expect(original.toString(), contains('SSH_Message_KexDH_Reply'));
    });

    test('carries the right message id', () {
      final encoded = SSH_Message_KexDH_Reply(
        hostPublicKey: hostKey,
        f: BigInt.one,
        signature: signature,
      ).encode();

      expect(SSHMessage.readMessageId(encoded), 31);
    });

    test('handles empty host key and signature', () {
      final original = SSH_Message_KexDH_Reply(
        hostPublicKey: Uint8List(0),
        f: BigInt.zero,
        signature: Uint8List(0),
      );
      final decoded = SSH_Message_KexDH_Reply.decode(original.encode());

      expect(decoded.hostPublicKey, isEmpty);
      expect(decoded.signature, isEmpty);
      expect(decoded.f, BigInt.zero);
    });
  });

  group('SSH_Message_KexDH_GexRequest', () {
    test('round-trips', () {
      final original = SSH_Message_KexDH_GexRequest(
        minN: 1024,
        preferredN: 2048,
        maxN: 8192,
      );
      final decoded = SSH_Message_KexDH_GexRequest.decode(original.encode());

      expect(decoded.minN, 1024);
      expect(decoded.preferredN, 2048);
      expect(decoded.maxN, 8192);
      expect(original.toString(), contains('preferredN: 2048'));
    });

    test('carries the right message id', () {
      final encoded = SSH_Message_KexDH_GexRequest(
        minN: 1,
        preferredN: 2,
        maxN: 3,
      ).encode();

      expect(SSHMessage.readMessageId(encoded), 34);
    });
  });

  group('SSH_Message_KexDH_GexGroup', () {
    test('round-trips', () {
      final original = SSH_Message_KexDH_GexGroup(p: big, g: BigInt.two);
      final decoded = SSH_Message_KexDH_GexGroup.decode(original.encode());

      expect(decoded.p, big);
      expect(decoded.g, BigInt.two);
      expect(original.toString(), contains('SSH_Message_KexDH_GexGroup'));
    });

    test('carries the right message id', () {
      final encoded =
          SSH_Message_KexDH_GexGroup(p: BigInt.one, g: BigInt.two).encode();

      expect(SSHMessage.readMessageId(encoded), 31);
    });
  });

  group('SSH_Message_KexDH_GexInit', () {
    test('round-trips', () {
      final original = SSH_Message_KexDH_GexInit(e: big);
      final decoded = SSH_Message_KexDH_GexInit.decode(original.encode());

      expect(decoded.e, big);
      expect(original.toString(), contains('e: $big'));
    });

    test('carries the right message id', () {
      final encoded = SSH_Message_KexDH_GexInit(e: BigInt.one).encode();

      expect(SSHMessage.readMessageId(encoded), 32);
    });
  });

  group('SSH_Message_KexDH_GexReply', () {
    test('round-trips', () {
      final original = SSH_Message_KexDH_GexReply(
        hostPublicKey: hostKey,
        f: big,
        signature: signature,
      );
      final decoded = SSH_Message_KexDH_GexReply.decode(original.encode());

      expect(decoded.hostPublicKey, hostKey);
      expect(decoded.f, big);
      expect(decoded.signature, signature);
      expect(original.toString(), contains('SSH_Message_KexDH_GexReply'));
    });

    test('carries a different message id than the plain reply', () {
      final encoded = SSH_Message_KexDH_GexReply(
        hostPublicKey: hostKey,
        f: BigInt.one,
        signature: signature,
      ).encode();

      expect(SSHMessage.readMessageId(encoded), 33);
      expect(SSH_Message_KexDH_GexReply.messageId,
          isNot(SSH_Message_KexDH_Reply.messageId));
    });

    test('is usable where a plain reply is expected', () {
      // The transport handles both replies through the same code path, so the
      // group-exchange variant must stay assignable to the base type.
      final SSH_Message_KexDH_Reply reply = SSH_Message_KexDH_GexReply(
        hostPublicKey: hostKey,
        f: big,
        signature: signature,
      );

      expect(reply.f, big);
      expect(reply.hostPublicKey, hostKey);
    });
  });
}
