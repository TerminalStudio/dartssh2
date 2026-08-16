import 'package:dartssh2/src/ssh_channel.dart';
import 'package:test/test.dart';

void main() {
  test('exposes distinct local and remote channel IDs', () {
    final controller = SSHChannelController(
      localId: 1,
      localMaximumPacketSize: 1024,
      localInitialWindowSize: 1024,
      remoteId: 42,
      remoteMaximumPacketSize: 1024,
      remoteInitialWindowSize: 0,
      sendMessage: (_) {},
    );

    final channel = controller.channel;

    expect(channel.channelId, 1);
    expect(channel.remoteChannelId, 42);
  });
}
