import 'dart:convert';
import 'dart:typed_data';

import 'package:dartssh3/src/utils/int.dart';
import 'package:dartssh3/src/utils/bigint.dart';
import 'package:dartssh3/src/utils/utf8.dart';

abstract class SSHMessage {
  /// Encode the message to SSH encoded data.
  Uint8List encode();

  static int readMessageId(Uint8List bytes) {
    return bytes[0];
  }
}

class SSHMessageReader {
  /// Message data.
  final Uint8List data;

  SSHMessageReader(this.data) : _byteData = ByteData.sublistView(data);

  /// ByteData view of [data], used for reading numbers.
  final ByteData _byteData;

  /// The current position in the message.
  var _offset = 0;

  bool get isDone => _offset >= data.length;

  void skip(int bytes) {
    _offset += bytes;
  }

  bool readBool() {
    return readUint8() != 0;
  }

  int readUint8() {
    return _byteData.getUint8(_offset++);
  }

  int readUint16() {
    final value = _byteData.getUint16(_offset);
    _offset += 2;
    return value;
  }

  int readUint32() {
    final value = _byteData.getUint32(_offset);
    _offset += 4;
    return value;
  }

  int readUint64() {
    final value = _byteData.getUint64(_offset);
    _offset += 8;
    return value;
  }

  Uint8List readBytes(int length) {
    final value = Uint8List.view(_byteData.buffer, _offset, length);
    _offset += length;
    return value;
  }

  Uint8List readString() {
    final length = readUint32();
    final value = Uint8List.sublistView(data, _offset, _offset + length);
    _offset += length;
    return value;
  }

  String readUtf8() {
    return utf8.decode(readString());
  }

  List<String> readNameList() {
    final string = utf8.decode(readString());
    final list = string.split(',');
    return list;
  }

  List<Uint8List> readStringList() {
    final list = <Uint8List>[];
    while (!isDone) {
      list.add(readString());
    }
    return list;
  }

  BigInt readMpint() {
    final magnitude = readString();
    final value = decodeBigIntWithSign(1, magnitude);
    return value;
  }

  Uint8List readToEnd() {
    final value = Uint8List.sublistView(data, _offset);
    _offset = data.length;
    return value;
  }
}

class SSHMessageWriter {
  SSHMessageWriter({bool copy = false}) : _builder = BytesBuilder(copy: copy);

  final BytesBuilder _builder;

  int get length => _builder.length;

  void writeBool(bool value) {
    _builder.addByte(value ? 1 : 0);
  }

  void writeUint8(int value) {
    _builder.addByte(value);
  }

  // void writeUint16(int value) {
  //   _builder.addByte(value >> 8);
  //   _builder.addByte(value);
  // }

  void writeUint32(int value) {
    _builder.add(value.toUint32());
  }

  void writeUint64(int value) {
    _builder.add(value.toUint64());
  }

  /// Write fixed length string.
  void writeBytes(Uint8List value) {
    _builder.add(value);
  }

  /// Write variable length string.
  void writeString(Uint8List value) {
    writeUint32(value.length);
    writeBytes(value);
  }

  void writeUtf8(String value) {
    writeString(utf8Encode(value));
  }

  /// Write comma separated list of names as a string.
  void writeNameList(List<String> value) {
    writeString(Utf8Encoder().convert(value.join(',')));
  }

  /// Write multiple precision integer as a string.
  void writeMpint(BigInt value) {
    writeString(encodeBigInt(value));
  }

  Uint8List takeBytes() {
    return _builder.takeBytes();
  }
}
