import 'dart:math';

/// "Securely" clears the given [buffer]. This is done by overwriting the
/// buffer with random data. Mainly used to ensure that sensitive data
/// (e.g. passwords) are not leaked to the heap.
void eraseList(List<int> buffer) {
  final random = Random();
  for (int i = 0; i < buffer.length; i++) {
    buffer[i] ^= random.nextInt(255);
  }
}
