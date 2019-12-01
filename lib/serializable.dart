// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:typed_data';

/// Rounds [input] up to the nearest [n]th.
int nextMultipleOfN(int input, int n) =>
    (input % n != 0) ? (input ~/ n + 1) * n : input;

/// Returns concatenation of [x] and [y].
Uint8List appendUint8List(Uint8List x, Uint8List y) =>
    Uint8List.fromList(x + y);

/// Returns view of [x], accounting for when [x] is another view.
Uint8List viewUint8List(Uint8List x, [int offset = 0, int length]) =>
    Uint8List.view(x.buffer, x.offsetInBytes + offset, length ?? x.length);

/// Returns the position of the first match of [needle] in [haystack] or -1.
int searchUint8List(Uint8List haystack, Uint8List needle) {
  if (needle.isEmpty) return -1;
  for (int i = 0; i < haystack.length - needle.length + 1; i++) {
    int j = 0;
    while (j < needle.length && haystack[i + j] == needle[j]) {
      j++;
    }
    if (j == needle.length) return i;
  }
  return -1;
}

/// Returns true if [x] and [y] are equivalent.
bool equalUint8List(Uint8List x, Uint8List y) {
  if (x.length != y.length) return false;
  for (int i = 0; i < x.length; ++i) {
    if (x[i] != y[i]) return false;
  }
  return true;
}

/// A [Uint8List] deque for consuming binary protocol.
class QueueBuffer {
  Uint8List data;
  QueueBuffer(this.data);

  /// Appends [x] to [data].
  void add(Uint8List x) => data = Uint8List.fromList((data ?? []) + x);

  /// Removes [0..x] of [data].
  void flush(int x) => data = data.sublist(x);
}

/// Base class for advancing [offset] view of Uint8List [data].
abstract class SerializableBuffer {
  int offset = 0;
  final Uint8List buffer;
  final ByteData data;
  final Endian endian;
  SerializableBuffer(this.buffer, {this.endian = Endian.big})
      : this.data =
            ByteData.view(buffer.buffer, buffer.offsetInBytes, buffer.length);

  bool get done => offset == buffer.length;
  int get remaining => buffer.length - offset;

  Uint8List view() => viewOffset(0, offset);
  Uint8List viewRemaining() => viewOffset(offset, buffer.length);
  Uint8List viewOffset(int start, int end) =>
      viewUint8List(buffer, start, end - start);
}

/// Consumes [SerializableBuffer] to deserialized input.
class SerializableInput extends SerializableBuffer {
  SerializableInput(Uint8List buffer, {Endian endian = Endian.big})
      : super(buffer, endian: endian);

  bool getBool() => getUint8() == 0 ? false : true;

  int getUint8() {
    offset++;
    return data.getUint8(offset - 1);
  }

  int getUint16() {
    offset += 2;
    return data.getUint16(offset - 2, endian);
  }

  int getUint32() {
    offset += 4;
    return data.getUint32(offset - 4, endian);
  }

  int getUint64() {
    offset += 8;
    return data.getUint64(offset - 8, endian);
  }

  Uint8List getBytes(int length) {
    offset += length;
    return viewOffset(offset - length, offset);
  }
}

/// Fills [SerializableBuffer] with serialized output.
class SerializableOutput extends SerializableBuffer {
  SerializableOutput(Uint8List buffer, {Endian endian = Endian.big})
      : super(buffer, endian: endian);

  void addUint8(int x) {
    data.setUint8(offset, x);
    offset++;
  }

  void addUint16(int x) {
    data.setUint16(offset, x, endian);
    offset += 2;
  }

  void addUint32(int x) {
    data.setUint32(offset, x, endian);
    offset += 4;
  }

  void addUint64(int x) {
    data.setUint64(offset, x, endian);
    offset += 8;
  }

  void addBytes(Uint8List x) {
    buffer.setRange(offset, offset + x.length, x);
    offset += x.length;
  }
}

// Interface implemented by serializable objects.
abstract class Serializable {
  /// Minimum size for this serialized object.
  int get serializedHeaderSize => null;

  /// Exact size for this serialized object.
  int get serializedSize;

  /// Interface for output serialization.
  void serialize(SerializableOutput output);

  /// Interface for intput serialization.
  void deserialize(SerializableInput input);

  /// Serializes this [Serializable] to a [Uint8List].
  Uint8List toRaw({Endian endian = Endian.big}) {
    SerializableOutput ret =
        SerializableOutput(Uint8List(serializedSize), endian: endian);
    serialize(ret);
    if (!ret.done) {
      throw FormatException('${ret.offset}/${ret.buffer.length}');
    }
    return ret.buffer;
  }

  /// Deserializes this [Serializable] from a [SerializableInput].
  void fromRaw(SerializableInput input) {
    deserialize(input);
    if (!input.done) {
      throw FormatException('${input.offset}/${input.buffer.length}');
    }
  }
}
