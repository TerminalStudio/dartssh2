// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:typed_data';

abstract class SerializableBuffer {
  int offset = 0;
  Uint8List buffer;
  ByteData data;
  Endian endian;
  SerializableBuffer(this.buffer, {this.endian = Endian.little})
      : this.data = ByteData.view(buffer.buffer);

  bool get done => offset == buffer.length;
  int get remaining => buffer.length - offset;

  Uint8List view() => viewOffset(0, offset);
  Uint8List viewOffset(int start, int end) =>
      Uint8List.view(buffer.buffer, start, end - start);
}

class SerializableInput extends SerializableBuffer {
  SerializableInput(Uint8List buffer, {Endian endian = Endian.little})
      : super(buffer, endian: endian);

  int getUint8() {
    offset++;
    return data.getUint8(offset - 1);
  }

  int getUint16() {
    offset += 2;
    return data.getUint16(offset - 2);
  }

  int getUint32() {
    offset += 4;
    return data.getUint32(offset - 4);
  }

  int getUint64() {
    offset += 8;
    return data.getUint64(offset - 8);
  }

  Uint8List getBytes(int length) {
    offset += length;
    return viewOffset(offset - length, offset);
  }
}

class SerializableOutput extends SerializableBuffer {
  SerializableOutput(Uint8List buffer, {Endian endian = Endian.little})
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

abstract class Serializable {
  /// Minimum size for this serialized object.
  int get serializedHeaderSize => null;

  /// Exact size for this serialized object.
  int get serializedSize;

  /// Interface for output serialization.
  void serialize(SerializableOutput output);

  /// Interface for intput serialization.
  void deserialize(SerializableInput input);

  Uint8List toRaw() {
    SerializableOutput ret = SerializableOutput(Uint8List(serializedSize));
    serialize(ret);
    assert(ret.done);
    return ret.buffer;
  }
}
