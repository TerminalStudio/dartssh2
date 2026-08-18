import 'dart:math';
import 'dart:typed_data';

import 'package:dartssh2/src/message/msg_channel.dart';
import 'package:dartssh2/src/message/msg_disconnect.dart';
import 'package:dartssh2/src/message/msg_kex.dart';
import 'package:dartssh2/src/message/msg_userauth.dart';
import 'package:dartssh2/src/sftp/sftp_packet.dart';
import 'package:dartssh2/src/ssh_errors.dart';
import 'package:dartssh2/src/ssh_message.dart';
import 'package:test/test.dart';

/// Decoders that parse bytes supplied by the peer.
final _decoders = <String, void Function(Uint8List)>{
  'SSH_Message_Channel_Request': SSH_Message_Channel_Request.decode,
  'SSH_Message_Channel_Open': SSH_Message_Channel_Open.decode,
  'SSH_Message_Channel_Data': SSH_Message_Channel_Data.decode,
  'SSH_Message_Disconnect': SSH_Message_Disconnect.decode,
  'SSH_Message_KexInit': SSH_Message_KexInit.decode,
  'SSH_Message_Userauth_Request': SSH_Message_Userauth_Request.decode,
  'SftpReadPacket': SftpReadPacket.decode,
  'SftpDataPacket': SftpDataPacket.decode,
  'SftpStatusPacket': SftpStatusPacket.decode,
  'SftpNamePacket': SftpNamePacket.decode,
};

/// A malformed packet is the peer's fault, so it has to surface as a protocol
/// error. `RangeError` and `IndexError` are Dart's way of reporting a bug in
/// the caller: a handler that catches [SSHError] would miss them, and inside a
/// stream callback they escape as an uncaught error.
void _expectProtocolError(String name, Uint8List input, Object error) {
  expect(
    error,
    isA<SSHError>(),
    reason: '$name threw ${error.runtimeType} on ${input.length} bytes '
        'of malformed input, which callers cannot tell from a library bug',
  );
}

void main() {
  group('decoders reject malformed input as a protocol error', () {
    test('random bytes', () {
      final random = Random(20260818);

      for (final entry in _decoders.entries) {
        for (var i = 0; i < 2000; i++) {
          final input = Uint8List.fromList(
            List<int>.generate(random.nextInt(64), (_) => random.nextInt(256)),
          );
          try {
            entry.value(input);
          } catch (error) {
            _expectProtocolError(entry.key, input, error);
          }
        }
      }
    });

    test('valid messages truncated at every length', () {
      final samples = <String, Uint8List>{
        'SSH_Message_Channel_Data': SSH_Message_Channel_Data(
          recipientChannel: 7,
          data: Uint8List.fromList([1, 2, 3, 4, 5]),
        ).encode(),
        'SSH_Message_Disconnect': SSH_Message_Disconnect(
          reasonCode: 11,
          description: 'bye',
        ).encode(),
        'SftpStatusPacket': SftpStatusPacket(
          requestId: 3,
          code: 4,
          message: 'failure',
        ).encode(),
      };

      samples.forEach((name, encoded) {
        for (var length = 0; length < encoded.length; length++) {
          final input = Uint8List.sublistView(encoded, 0, length);
          try {
            _decoders[name]!(input);
          } catch (error) {
            _expectProtocolError(name, input, error);
          }
        }
      });
    });
  });

  group('SSHMessageReader', () {
    test('reads bytes relative to the message, not the backing buffer', () {
      // SSH and SFTP payloads are routinely views carved out of a larger
      // receive buffer, so a reader built on one must not index the buffer.
      final backing = Uint8List.fromList(
        List<int>.generate(24, (i) => i < 8 ? 0xee : 0xa0 + (i - 8)),
      );
      final message = Uint8List.sublistView(backing, 8);

      final reader = SSHMessageReader(message);

      expect(reader.readBytes(4), [0xa0, 0xa1, 0xa2, 0xa3]);
    });

    test('running past the end is a protocol error', () {
      final reader = SSHMessageReader(Uint8List(3));

      expect(() => reader.readUint32(), throwsA(isA<SSHPacketError>()));
      expect(() => reader.readBytes(9), throwsA(isA<SSHPacketError>()));
    });
  });
}
