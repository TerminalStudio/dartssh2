// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:typed_data';

import 'package:dartssh/protocol.dart';
import 'package:dartssh/serializable.dart';

class PEM {
  String text;
  PEM(this.text);

  String parseHeader() {}
}

class OpenSSHKey extends Serializable {
  String magic = 'openssh-key-v1', ciphername, kdfname, kdfoptions, privatekey;
  List<String> publickeys;
  OpenSSHKey([this.ciphername, this.kdfname, this.kdfoptions, this.privatekey]);

  @override
  int get serializedHeaderSize => 5 * 4 + 15;

  @override
  int get serializedSize =>
      serializedHeaderSize +
      ciphername.length +
      kdfname.length +
      kdfoptions.length +
      privatekey.length +
      publickeys.fold(0, (v, e) => v += e.length);

  @override
  void deserialize(SerializableInput input) {
    Uint8List nullTerminatedMagic = input.getBytes(15);
    magic = String.fromCharCodes(nullTerminatedMagic, 0, 14);
    if (magic != 'openssh-key-v1') throw FormatException('wrong magic: $magic');

    ciphername = deserializeString(input);
    kdfname = deserializeString(input);
    kdfoptions = deserializeString(input);
    publickeys = List<String>(input.getUint32());
    for (int i = 0; i < publickeys.length; i++) {
      publickeys[i] = deserializeString(input);
    }
    privatekey = deserializeString(input);
  }

  @override
  void serialize(SerializableOutput output) {
    output.addBytes(magic.codeUnits);
    output.addUint8(0);

    serializeString(output, ciphername);
    serializeString(output, kdfname);
    serializeString(output, kdfoptions);
    output.addUint32(publickeys.length);
    for (String publickey in publickeys) {
      serializeString(output, publickey);
    }
    serializeString(output, privatekey);
  }
}

class OpenSSHPrivateKeyHeader extends Serializable {
  int checkint1 = 0, checkint2 = 0;
  OpenSSHPrivateKeyHeader();

  @override
  int get serializedHeaderSize => 2 * 4;

  @override
  int get serializedSize => serializedHeaderSize;

  @override
  void deserialize(SerializableInput input) {
    checkint1 = input.getUint32();
    checkint2 = input.getUint32();
    if (checkint1 != checkint2) {
      throw FormatException('$checkint1 != $checkint2');
    }
  }

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(checkint1);
    output.addUint32(checkint2);
  }
}

class OpenSSHEd25519PrivateKey extends Serializable {
  String keytype = 'ssh-ed25519', pubkey, privkey, comment;
  OpenSSHEd25519PrivateKey([this.pubkey, this.privkey, this.comment]);

  @override
  int get serializedHeaderSize => 4 * 4;

  @override
  int get serializedSize =>
      serializedHeaderSize +
      keytype.length +
      pubkey.length +
      privkey.length +
      comment.length;

  @override
  void deserialize(SerializableInput input) {
    keytype = deserializeString(input);
    if (keytype != 'ssh-ed25519') throw FormatException('$keytype');
    pubkey = deserializeString(input);
    if (pubkey.length != 32) throw FormatException('${pubkey.length}');
    privkey = deserializeString(input);
    if (privkey.length != 64) throw FormatException('${privkey.length}');
    comment = deserializeString(input);
  }

  @override
  void serialize(SerializableOutput output) {
    serializeString(output, keytype);
    serializeString(output, pubkey);
    serializeString(output, privkey);
    serializeString(output, comment);
  }
}

class OpenSSHBCryptKDFOptions extends Serializable {
  String salt;
  int rounds;
  OpenSSHBCryptKDFOptions([this.salt, this.rounds]);

  @override
  int get serializedHeaderSize => 2 * 4;

  @override
  int get serializedSize => serializedHeaderSize + salt.length;

  @override
  void deserialize(SerializableInput input) {
    salt = deserializeString(input);
    rounds = input.getUint32();
  }

  @override
  void serialize(SerializableOutput output) {
    serializeString(output, salt);
    output.addUint32(rounds);
  }
}
