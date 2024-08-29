import 'dart:typed_data';

import 'package:dartssh2/src/utils/stream.dart';
import 'package:test/test.dart';

void main() {
  group('StreamConsumer', () {
    test('works', () async {
      final stream = Stream.fromIterable([
        Uint8List.fromList([1, 2, 3, 4, 5]),
        Uint8List.fromList([6, 7, 8, 9, 10]),
      ]);
      final consumer = StreamConsumer(stream);

      expect(
        await consumer.read(3),
        equals(Uint8List.fromList([1, 2, 3])),
      );
      expect(
        await consumer.read(3),
        equals(Uint8List.fromList([4, 5])),
      );
      expect(
        await consumer.read(5),
        equals(Uint8List.fromList([6, 7, 8, 9, 10])),
      );
      expect(await consumer.read(1), isNull);
    });

    test('has a fast path to read entire chunk', () async {
      final chunk1 = Uint8List.fromList([1, 2, 3, 4, 5]);
      final chunk2 = Uint8List.fromList([6, 7, 8, 9, 10]);
      final stream = Stream.fromIterable([chunk1, chunk2]);
      final consumer = StreamConsumer(stream);

      expect(identical(await consumer.read(5), chunk1), isTrue);
      expect(identical(await consumer.read(6), chunk2), isTrue);
      expect(await consumer.read(1), isNull);
    });

    test('always return null after done', () async {
      final stream = Stream.fromIterable([
        Uint8List.fromList([1, 2, 3, 4, 5]),
      ]);

      final consumer = StreamConsumer(stream);
      await consumer.read(5);

      expect(await consumer.read(1), isNull);
      expect(await consumer.read(1), isNull);
      expect(await consumer.read(1), isNull);
    });
  });
}
