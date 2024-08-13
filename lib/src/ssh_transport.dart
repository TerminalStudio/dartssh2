import 'dart:async';
import 'dart:convert';
import 'dart:math' show max;
import 'dart:typed_data';

import 'package:dartssh3/src/algorithm/ssh_cipher_type.dart';
import 'package:dartssh3/src/algorithm/ssh_hostkey_type.dart';
import 'package:dartssh3/src/algorithm/ssh_kex_type.dart';
import 'package:dartssh3/src/algorithm/ssh_mac_type.dart';
import 'package:dartssh3/src/hostkey/hostkey_ecdsa.dart';
import 'package:dartssh3/src/hostkey/hostkey_rsa.dart';
import 'package:dartssh3/src/kex/kex_dh.dart';
import 'package:dartssh3/src/kex/kex_nist.dart';
import 'package:dartssh3/src/kex/kex_x25519.dart';
import 'package:dartssh3/src/message/msg_userauth.dart';
import 'package:dartssh3/src/socket/ssh_socket.dart';
import 'package:dartssh3/src/ssh_algorithm.dart';
import 'package:dartssh3/src/ssh_kex.dart';
import 'package:dartssh3/src/utils/bigint.dart';
import 'package:dartssh3/src/utils/cipher_ext.dart';
import 'package:dartssh3/src/utils/chunk_buffer.dart';
import 'package:dartssh3/src/ssh_errors.dart';
import 'package:dartssh3/src/ssh_kex_utils.dart';
import 'package:dartssh3/src/ssh_packet.dart';
import 'package:dartssh3/src/utils/int.dart';
import 'package:dartssh3/src/hostkey/hostkey_ed25519.dart';
import 'package:dartssh3/src/utils/list.dart';
import 'package:dartssh3/src/message/msg_kex.dart';
import 'package:dartssh3/src/message/msg_kex_dh.dart';
import 'package:dartssh3/src/message/msg_kex_ecdh.dart';
import 'package:dartssh3/src/ssh_message.dart';
import 'package:pointycastle/export.dart';

typedef SSHPrintHandler = void Function(String?);

/// Function called when host key is received.
/// [type] is the type of the host key, For example 'ssh-rsa',
/// [fingerprint] md5 fingerprint of the host key.
typedef SSHHostkeyVerifyHandler = FutureOr<bool> Function(
  String type,
  Uint8List fingerprint,
);

typedef SSHTransportReadyHandler = void Function();

typedef SSHPacketHandler = void Function(Uint8List payload);

class SSHTransport {
  /// Version of the SSH software. By default "DartSSH_2.0"
  final String version;

  /// The socket to read and write data to.
  final SSHSocket socket;

  /// Whether the transport acts as a server.
  final bool isServer;

  /// Whether the transport acts as a client. This is equal to `!isServer`.
  bool get isClient => !isServer;

  /// Function invoked with debug logging.
  final SSHPrintHandler? printDebug;

  /// Function invoked with trace logging.
  final SSHPrintHandler? printTrace;

  final SSHAlgorithms algorithms;

  /// Function called when the hostkey has been received. Returns true if the
  /// hostkey is valid, false to reject key and disconnect.
  final SSHHostkeyVerifyHandler? onVerifyHostKey;

  /// Function called when the transport is ready to send data.
  final SSHTransportReadyHandler? onReady;

  /// Function called when a packet is received.
  final SSHPacketHandler? onPacket;

  /// A [Future] that completes when the transport is closed, or when an error
  /// occurs. After this [Future] completes, [isClosed] will be true and no
  /// more data can be sent or received.
  Future<void> get done => _doneCompleter.future;

  /// `true` if the connection is closed normally or due to an error.
  bool get isClosed => _doneCompleter.isCompleted;

  /// Identification string sent by the other side. For example, "SSH-2.0-OpenSSH_7.4p1".
  /// May be `null` if the handshake has not yet completed.
  String? get remoteVersion => _remoteVersion;

  SSHTransport(
    this.socket, {
    this.isServer = false,
    this.version = 'DartSSH_2.0',
    this.printDebug,
    this.printTrace,
    this.algorithms = const SSHAlgorithms(),
    this.onVerifyHostKey,
    this.onReady,
    this.onPacket,
  }) {
    _initSocket();
    _startHandshake();
  }

  final _doneCompleter = Completer<void>();

  /// Contains unprocessed data from the socket.
  final _buffer = ChunkBuffer();

  /// Contains decrypted packet data. May be partial.
  final _decryptBuffer = ChunkBuffer();

  /// Subscription to the socket's [Stream]. It should be closed when the
  /// transport is closed.
  StreamSubscription? _socketSubscription;

  /// Identification string sent by us without trailing \r\n. For example,
  /// "SSH-2.0-DartSSH_2.0".
  String get _localVersion => 'SSH-2.0-$version';

  /// Identification string sent by the other side. For example, "SSH-2.0-OpenSSH_7.4p1".
  /// May be `null` if the handshake has not yet completed.
  /// This is kept to compute [_exchangeHash]
  String? _remoteVersion;

  /// Payload of the [SSH_Message_KexInit] sent by us. Kept to compute the
  /// exchange hash.
  late Uint8List _localKexInit;

  /// Payload of the [SSH_Message_KexInit] sent by the other side. Kept to
  /// compute the exchange hash.
  late Uint8List _remoteKexInit;

  SSHKexType? _kexType;

  SSHHostkeyType? _hostkeyType;

  SSHCipherType? _clientCipherType;

  SSHCipherType? _serverCipherType;

  SSHMacType? _clientMacType;

  SSHMacType? _serverMacType;

  SSHKex? _kex;

  /// [_exchangeHash] of the first key exchange is used as session identifier.
  /// Used to derive the cipher IV, cipher key and MAC key.
  Uint8List? _sessionId;

  /// A hash value of various parameters (defined in rfc4253). Kept to derive the
  /// cipher IV, cipher key and MAC key.
  Uint8List? _exchangeHash;

  /// Whether the hostkey of the server has been verified. This is always false
  /// when the transport is acting as a server.
  var _hostkeyVerified = false;

  /// Shared secret derived from the key exchange process. Kept to derive the
  /// cipher IV, cipher key and MAC key.
  BigInt? _sharedSecret;

  /// A [BlockCipher] to encrypt data sent to the other side.
  BlockCipher? _encryptCipher;

  /// A [BlockCipher] to decrypt data sent from the other side.
  BlockCipher? _decryptCipher;

  /// A [Mac] used to authenticate data sent to the other side.
  Mac? _localMac;

  /// A [Mac] used to authenticate data sent from the other side.
  Mac? _remoteMac;

  final _localPacketSN = SSHPacketSN.fromZero();

  final _remotePacketSN = SSHPacketSN.fromZero();

  void sendPacket(Uint8List data) {
    if (isClosed) {
      throw SSHStateError('Transport is closed');
    }
    final packetAlign = _encryptCipher == null
        ? SSHPacket.minAlign
        : max(SSHPacket.minAlign, _encryptCipher!.blockSize);

    final packet = SSHPacket.pack(data, align: packetAlign);

    if (_encryptCipher == null) {
      socket.sink.add(packet);
    } else {
      final mac = _localMac!;
      mac.updateAll(_localPacketSN.value.toUint32());
      mac.updateAll(packet);

      final buffer = BytesBuilder(copy: false);
      buffer.add(_encryptCipher!.processAll(packet));
      buffer.add(mac.finish());

      socket.sink.add(buffer.takeBytes());
    }

    _localPacketSN.increase();
  }

  void close() {
    printDebug?.call('SSHTransport.close');
    if (isClosed) return;
    _socketSubscription?.cancel();
    _socketSubscription = null;
    _doneCompleter.complete();
    socket.destroy();
  }

  void closeWithError(SSHError error, [StackTrace? stackTrace]) {
    printDebug?.call('SSHTransport.closeWithError $error');
    if (isClosed) return;
    _socketSubscription?.cancel();
    _socketSubscription = null;
    _doneCompleter.completeError(error, stackTrace ?? StackTrace.current);
    socket.destroy();
  }

  void _initSocket() {
    _socketSubscription = socket.stream.listen(
      _onSocketData,
      onError: _onSocketError,
      onDone: _onSocketDone,
    );

    socket.done.catchError(_onSocketError);
  }

  void _onSocketData(Uint8List data) {
    _buffer.add(data);
    try {
      _processData();
    } on SSHError catch (e, stackTrace) {
      closeWithError(e, stackTrace);
    } catch (e) {
      rethrow;
    }
  }

  void _onSocketError(Object error, StackTrace stackTrace) {
    printDebug?.call('SSHTransport._onSocketError($error)');
    closeWithError(SSHSocketError(error), stackTrace);
  }

  void _onSocketDone() {
    printDebug?.call('SSHTransport._onSocketDone');
    close();
  }

  void _processData() {
    if (_remoteVersion == null) {
      _processVersionExchange();
    } else {
      _processPackets();
    }
  }

  void _processVersionExchange() {
    printDebug?.call('SSHTransport._processVersionExchange');

    if (_buffer.length > 10240) {
      throw SSHHandshakeError('Version exchange too long');
    }

    final bufferString = latin1.decode(_buffer.data);

    // SSH version exchange is terminated by \r\n.
    var index = bufferString.indexOf('\r\n');
    if (index == -1) {
      // In the (rare) case SSH-2 version string is terminated by \n only (observed on Synology DS120j 2021)
      index = bufferString.indexOf('\n');
      if (index == -1) {
        throw SSHHandshakeError('Version exchange not terminated');
      }
      _buffer.consume(index + 1);
    } else {
      _buffer.consume(index + 2);
    }

    final versionString = bufferString.substring(0, index);
    if (!versionString.startsWith('SSH-2.0-')) {
      socket.sink.add(latin1.encode('Protocol mismatch\r\n'));
      throw SSHHandshakeError('Invalid version: $versionString');
    }

    printTrace?.call('<- $socket: $versionString');
    printDebug?.call('SSHTransport._remoteVersion = "$versionString"');
    _remoteVersion = versionString;

    if (isServer) {
      _sendKexInit();
    }

    // There maybe more data in the buffer, so process it.
    _processPackets();
  }

  /// Process one or more SSH packets queued in [_buffer].
  void _processPackets() {
    printDebug?.call('SSHTransport._processPackets');

    while (_buffer.isNotEmpty && !isClosed) {
      final payload = _consumePacket();
      if (payload == null) {
        break;
      }

      // if (payload.length > SSHPacket.maxPayloadLength) {
      //   throw SSHPacketError('Packet too long: ${payload.length}');
      // }

      _handleMessage(payload);

      _remotePacketSN.increase();
    }
  }

  /// Reads a single SSH packet from the buffer. Returns payload of the packet
  /// WITHOUT `packet length`, `padding length`, `padding` and `MAC`. Returns
  /// `null` if there is not enough data in the buffer to read the packet.
  Uint8List? _consumePacket() {
    return _decryptCipher == null
        ? _consumeClearTextPacket()
        : _consumeEncryptedPacket();
  }

  Uint8List? _consumeClearTextPacket() {
    printDebug?.call('SSHTransport._consumeClearTextPacket');

    if (_buffer.length < 4) {
      return null;
    }

    final packetLength = SSHPacket.readPacketLength(_buffer.data);
    _verifyPacketLength(packetLength);

    if (_buffer.length < packetLength + 4) {
      return null;
    }

    final packet = _buffer.consume(packetLength + 4);
    final paddingLength = SSHPacket.readPaddingLength(packet);
    final payloadLength = packetLength - paddingLength - 1;
    _verifyPacketPadding(payloadLength, paddingLength);

    return Uint8List.sublistView(packet, 5, packet.length - paddingLength);
  }

  Uint8List? _consumeEncryptedPacket() {
    printDebug?.call('SSHTransport._consumeEncryptedPacket');

    final blockSize = _decryptCipher!.blockSize;
    if (_buffer.length < blockSize) {
      return null;
    }

    if (_decryptBuffer.isEmpty) {
      final firstBlock = _buffer.consume(blockSize);
      _decryptBuffer.add(_decryptCipher!.process(firstBlock));
    }

    final packetLength = SSHPacket.readPacketLength(_decryptBuffer.data);
    _verifyPacketLength(packetLength);

    final macLength = _remoteMac!.macSize;
    if (_buffer.length + _decryptBuffer.length < 4 + packetLength + macLength) {
      return null;
    }

    while (_decryptBuffer.length < 4 + packetLength) {
      final block = _buffer.consume(blockSize);
      _decryptBuffer.add(_decryptCipher!.process(block));
    }

    final packet = _decryptBuffer.consume(packetLength + 4);
    final paddingLength = SSHPacket.readPaddingLength(packet);
    final payloadLength = packetLength - paddingLength - 1;
    _verifyPacketPadding(payloadLength, paddingLength);

    final mac = _buffer.consume(macLength);
    _verifyPacketMac(packet, mac);

    return Uint8List.sublistView(packet, 5, packet.length - paddingLength);
  }

  void _verifyPacketLength(int packetLength) {
    if (packetLength > SSHPacket.maxLength) {
      throw SSHPacketError('Packet too long: $packetLength');
    }
  }

  /// Verifies that the padding of the packet is correct. Throws [SSHPacketError]
  /// if the padding is incorrect.
  void _verifyPacketPadding(int payloadLength, int paddingLength) {
    final expectedPacketAlign = _decryptCipher == null
        ? SSHPacket.minAlign
        : max(SSHPacket.minAlign, _decryptCipher!.blockSize);

    final minPaddingLength = SSHPacket.paddingLength(
      payloadLength,
      align: expectedPacketAlign,
    );

    if (paddingLength < minPaddingLength) {
      throw SSHPacketError(
        'Invalid padding length: $paddingLength, expected: $minPaddingLength',
      );
    }
  }

  /// Verifies that the MAC of the packet is correct. Throws [SSHPacketError]
  /// if the MAC is incorrect.
  void _verifyPacketMac(Uint8List payload, Uint8List actualMac) {
    final macSize = _remoteMac!.macSize;
    if (actualMac.length != macSize) {
      throw ArgumentError.value(actualMac, 'mac', 'Invalid MAC size');
    }

    _remoteMac!.updateAll(_remotePacketSN.value.toUint32());
    _remoteMac!.updateAll(payload);
    final expectedMac = _remoteMac!.finish();

    if (!expectedMac.equals(actualMac)) {
      throw SSHPacketError(
        'MAC mismatch, expected: $expectedMac, actual: $actualMac',
      );
    }
  }

  void _startHandshake() {
    socket.sink.add(latin1.encode('$_localVersion\r\n'));

    if (isClient) {
      _sendKexInit();
    }
  }

  void _applyLocalKeys() {
    final cipherType = isClient ? _clientCipherType : _serverCipherType;
    if (cipherType == null) throw StateError('No cipher type selected');

    _encryptCipher = cipherType.createCipher(
      _deriveKey(
        isClient ? SSHDeriveKeyType.clientKey : SSHDeriveKeyType.serverKey,
        cipherType.keySize,
      ),
      _deriveKey(
        isClient ? SSHDeriveKeyType.clientIV : SSHDeriveKeyType.serverIV,
        cipherType.ivSize,
      ),
      forEncryption: true,
    );

    final macType = isClient ? _clientMacType : _serverMacType;
    if (macType == null) throw StateError('No MAC type selected');

    final macKey = _deriveKey(
      isClient ? SSHDeriveKeyType.clientMacKey : SSHDeriveKeyType.serverMacKey,
      macType.keySize,
    );

    _localMac = macType.createMac(macKey);
  }

  void _applyRemoteKeys() {
    final cipherType = isClient ? _serverCipherType : _clientCipherType;
    if (cipherType == null) throw StateError('No cipher type selected');

    _decryptCipher = cipherType.createCipher(
      _deriveKey(
        isClient ? SSHDeriveKeyType.serverKey : SSHDeriveKeyType.clientKey,
        cipherType.keySize,
      ),
      _deriveKey(
        isClient ? SSHDeriveKeyType.serverIV : SSHDeriveKeyType.clientIV,
        cipherType.ivSize,
      ),
      forEncryption: false,
    );

    final macType = isClient ? _serverMacType : _clientMacType;
    if (macType == null) throw StateError('No MAC type selected');

    final macKey = _deriveKey(
      isClient ? SSHDeriveKeyType.serverMacKey : SSHDeriveKeyType.clientMacKey,
      macType.keySize,
    );
    _remoteMac = macType.createMac(macKey);
  }

  Uint8List _deriveKey(SSHDeriveKeyType keyType, int keySize) {
    return SSHKexUtils.deriveKey(
      digest: _kexType!.createDigest(),
      sharedSecret: _sharedSecret!,
      exchangeHash: _exchangeHash!,
      keyType: keyType,
      sessionId: _sessionId!,
      keySize: keySize,
    );
  }

  /// Composes the data blob to be signed by the client with its public key.
  Uint8List composeChallenge({
    required String username,
    required String service,
    required String publicKeyAlgorithm,
    required Uint8List publicKey,
  }) {
    final writer = SSHMessageWriter();
    writer.writeString(_sessionId!);
    writer.writeUint8(SSH_Message_Userauth_Request.messageId);
    writer.writeUtf8(username);
    writer.writeUtf8(service);
    writer.writeUtf8('publickey');
    writer.writeBool(true);
    writer.writeUtf8(publicKeyAlgorithm);
    writer.writeString(publicKey);
    return writer.takeBytes();
  }

  bool _verifyHostkey({
    required Uint8List keyBytes,
    required Uint8List signatureBytes,
    required Uint8List exchangeHash,
  }) {
    switch (_hostkeyType) {
      case SSHHostkeyType.ed25519:
        final publicKey = SSHEd25519PublicKey.decode(keyBytes);
        final signature = SSHEd25519Signature.decode(signatureBytes);
        return publicKey.verify(exchangeHash, signature);
      case SSHHostkeyType.rsaSha1:
      case SSHHostkeyType.rsaSha256:
      case SSHHostkeyType.rsaSha512:
        final publicKey = SSHRsaPublicKey.decode(keyBytes);
        final signature = SSHRsaSignature.decode(signatureBytes);
        return publicKey.verify(exchangeHash, signature);
      case SSHHostkeyType.ecdsa256:
      case SSHHostkeyType.ecdsa384:
      case SSHHostkeyType.ecdsa521:
        final publicKey = SSHEcdsaPublicKey.decode(keyBytes);
        final signature = SSHEcdsaSignature.decode(signatureBytes);
        return publicKey.verify(exchangeHash, signature);
      case null:
        throw StateError('No hostkey type negotiated');
      default:
        throw UnimplementedError('Unsupported hostkey type: $_hostkeyType');
    }
  }

  void _sendKexInit() {
    printDebug?.call('SSHTransport._sendKexInit');

    final message = SSH_Message_KexInit(
      kexAlgorithms: algorithms.kex.toNameList(),
      // kexAlgorithms: ['curve25519-sha256'],
      serverHostKeyAlgorithms: algorithms.hostkey.toNameList(),
      encryptionClientToServer: algorithms.cipher.toNameList(),
      encryptionServerToClient: algorithms.cipher.toNameList(),
      macClientToServer: algorithms.mac.toNameList(),
      macServerToClient: algorithms.mac.toNameList(),
      compressionClientToServer: ['none'],
      compressionServerToClient: ['none'],
      firstKexPacketFollows: false,
    );

    final payload = message.encode();
    _localKexInit = payload;

    sendPacket(payload);
    printTrace?.call('-> $socket: $message');
  }

  /// Send diffie-hellman key exchange message. The exact message format depends
  /// on the negotiated key exchange algorithm.
  void _sendKexDHInit() {
    printDebug?.call('SSHTransport._sendKexDHInit');

    final kex = _kex;
    late final SSHMessage message;

    if (kex is SSHKexDH) {
      message = SSH_Message_KexDH_Init(e: kex.e);
    } else if (kex is SSHKexECDH) {
      message = SSH_Message_KexECDH_Init(kex.publicKey);
    } else {
      throw StateError('No key exchange algorithm negotiated');
    }

    sendPacket(message.encode());
    printTrace?.call('-> $socket: $message');
  }

  void _sendKexDHGexRequest() {
    printDebug?.call('SSHTransport._sendKexDHGexRequest');

    final message = SSH_Message_KexDH_GexRequest(
      minN: SSHKexDH.gexMin,
      preferredN: SSHKexDH.gexPref,
      maxN: SSHKexDH.gexMax,
    );

    sendPacket(message.encode());
    printTrace?.call('-> $socket: $message');
  }

  void _sendKexDHGexInit() {
    printDebug?.call('SSHTransport._sendKexDHGexInit');

    final kex = _kex;
    if (kex is! SSHKexDH) {
      throw StateError('kex is not SSHKexDH');
    }

    final message = SSH_Message_KexDH_GexInit(e: kex.e);
    sendPacket(message.encode());
    printTrace?.call('-> $socket: $message');
  }

  /// Sends [SSH_Message_NewKeys] message. After this message, all data sent
  /// to the server should be encrypted with the keys negotiated in key exchange.
  void _sendNewKeys() {
    printDebug?.call('SSHTransport._sendNewKeys');
    final message = SSH_Message_NewKeys();
    printTrace?.call('-> $socket: $message');
    sendPacket(message.encode());
  }

  void _handleMessage(Uint8List message) {
    final messageId = SSHMessage.readMessageId(message);
    switch (messageId) {
      case SSH_Message_KexInit.messageId:
        return _handleMessageKexInit(message);
      case SSH_Message_KexDH_Reply.messageId:
      case SSH_Message_KexDH_GexReply.messageId:
        return _handleMessageKexReply(message);
      case SSH_Message_NewKeys.messageId:
        return _handleMessageNewKeys(message);
      default:
        onPacket?.call(message);
    }
  }

  void _handleMessageKexInit(Uint8List payload) {
    printDebug?.call('SSHTransport._handleMessageKexInit');

    final message = SSH_Message_KexInit.decode(payload);
    printTrace?.call('<- $socket: $message');
    _remoteKexInit = payload;

    _kexType = SSHKexUtils.selectAlgorithm(
      localAlgorithms: algorithms.kex,
      remoteAlgorithms: message.kexAlgorithms,
      isServer: isServer,
    );
    _hostkeyType = SSHKexUtils.selectAlgorithm(
      localAlgorithms: algorithms.hostkey,
      remoteAlgorithms: message.serverHostKeyAlgorithms,
      isServer: isServer,
    );
    _clientCipherType = SSHKexUtils.selectAlgorithm(
      localAlgorithms: algorithms.cipher,
      remoteAlgorithms: message.encryptionClientToServer,
      isServer: isServer,
    );
    _serverCipherType = SSHKexUtils.selectAlgorithm(
      localAlgorithms: algorithms.cipher,
      remoteAlgorithms: message.encryptionServerToClient,
      isServer: isServer,
    );
    _clientMacType = SSHKexUtils.selectAlgorithm(
      localAlgorithms: algorithms.mac,
      remoteAlgorithms: message.macClientToServer,
      isServer: isServer,
    );
    _serverMacType = SSHKexUtils.selectAlgorithm(
      localAlgorithms: algorithms.mac,
      remoteAlgorithms: message.macServerToClient,
      isServer: isServer,
    );

    if (_kexType == null) {
      throw StateError('No matching key exchange algorithm');
    }
    if (_hostkeyType == null) {
      throw StateError('No matching host key algorithm');
    }
    if (_clientCipherType == null) {
      throw StateError('No matching client cipher algorithm');
    }
    if (_serverCipherType == null) {
      throw StateError('No matching server cipher algorithm');
    }
    if (_clientMacType == null) {
      throw StateError('No matching client MAC algorithm');
    }
    if (_serverMacType == null) {
      throw StateError('No matching server MAC algorithm');
    }

    printDebug?.call('SSHTransport._kexType: $_kexType');
    printDebug?.call('SSHTransport._hostkeyType: $_hostkeyType');
    printDebug?.call('SSHTransport._clientCipherType: $_clientCipherType');
    printDebug?.call('SSHTransport._serverCipherType: $_serverCipherType');
    printDebug?.call('SSHTransport._clientMacType: $_clientMacType');
    printDebug?.call('SSHTransport._serverMacType: $_serverMacType');

    switch (_kexType) {
      case SSHKexType.x25519:
        _kex = SSHKexX25519();
        break;
      case SSHKexType.nistp256:
        _kex = SSHKexNist.p256();
        break;
      case SSHKexType.nistp384:
        _kex = SSHKexNist.p384();
        break;
      case SSHKexType.nistp521:
        _kex = SSHKexNist.p521();
        break;
      case SSHKexType.dh14Sha1:
      case SSHKexType.dh14Sha256:
        _kex = SSHKexDH.group14();
        break;
      case SSHKexType.dh1Sha1:
        _kex = SSHKexDH.group1();
        break;
      case SSHKexType.dhGexSha1:
      case SSHKexType.dhGexSha256:
        if (isClient) _sendKexDHGexRequest();
        return;
      default:
        throw UnimplementedError('$_kexType');
    }

    if (isClient) {
      _sendKexDHInit();
    }
  }

  /// When client receives [SSH_Message_KexECDH_Reply], it should verify the
  /// server's signature with the server's public key. Then send NEW_KEYS
  /// message back to the server.
  void _handleMessageKexReply(Uint8List payload) {
    printDebug?.call('SSHTransport._handleMessageKexReply');
    if (isServer) throw SSHStateError('Unexpected KEX_REPLY');

    final kex = _kex;
    final kexType = _kexType;

    if (kexType == null) {
      throw SSHStateError('kexType has not been negotiated');
    }

    if (kex == null) {
      if (kexType.isGroupExchange == true) {
        return _handleMessageKexGexReply(payload);
      } else {
        throw SSHStateError('No key exchange algorithm');
      }
    }

    late Uint8List hostkey;
    late Uint8List hostSignature;
    late Uint8List serverKexKey;
    late Uint8List clientKexKey;
    late BigInt sharedSecret;

    if (kex is SSHKexDH) {
      final message = kexType.isGroupExchange
          ? SSH_Message_KexDH_GexReply.decode(payload)
          : SSH_Message_KexDH_Reply.decode(payload);
      printTrace?.call('<- $socket: $message');
      hostkey = message.hostPublicKey;
      hostSignature = message.signature;
      serverKexKey = encodeBigInt(message.f);
      clientKexKey = encodeBigInt(kex.e);
      sharedSecret = kex.computeSecret(message.f);
    } else if (kex is SSHKexECDH) {
      final message = SSH_Message_KexECDH_Reply.decode(payload);
      printTrace?.call('<- $socket: $message');
      hostkey = message.hostPublicKey;
      hostSignature = message.signature;
      serverKexKey = message.ecdhPublicKey;
      clientKexKey = kex.publicKey;
      sharedSecret = kex.computeSecret(message.ecdhPublicKey);
    } else {
      throw UnimplementedError('$kex');
    }

    final exchangeHash = SSHKexUtils.computeExchangeHash(
      digest: _kexType!.createDigest(),
      groupExchange: kexType.isGroupExchange ? kex as SSHKexDH : null,
      clientVersion: _localVersion,
      serverVersion: _remoteVersion!,
      clientKexInit: _localKexInit,
      serverKexInit: _remoteKexInit,
      hostKey: hostkey,
      clientPublicKey: clientKexKey,
      serverPublicKey: serverKexKey,
      sharedSecret: sharedSecret,
    );

    final verified = _verifyHostkey(
      keyBytes: hostkey,
      signatureBytes: hostSignature,
      exchangeHash: exchangeHash,
    );
    if (!verified) throw SSHHostkeyError('Signature verification failed');

    _exchangeHash = exchangeHash;
    _sessionId ??= exchangeHash;
    _sharedSecret = sharedSecret;

    final fingerprint = MD5Digest().process(hostkey);

    if (_hostkeyVerified) {
      _sendNewKeys();
      _applyLocalKeys();
      return;
    }

    final userVerified = onVerifyHostKey != null
        ? onVerifyHostKey!(_hostkeyType!.name, fingerprint)
        : true;

    Future.value(userVerified).then(
      (verified) {
        if (!verified) {
          closeWithError(SSHHostkeyError('Hostkey verification failed'));
        } else {
          _hostkeyVerified = true;
          _sendNewKeys();
          _applyLocalKeys();
          onReady?.call();
        }
      },
      onError: (error) {
        closeWithError(error);
      },
    );
  }

  void _handleMessageKexGexReply(Uint8List payload) {
    printDebug?.call('SSHTransport._handleMessageKexGexReply');
    if (isServer) throw SSHStateError('Unexpected KEX_GEX_REPLY');

    final message = SSH_Message_KexDH_GexGroup.decode(payload);
    printTrace?.call('<- $socket: $message');

    _kex = SSHKexDH(p: message.p, g: message.g, secretBits: 256);
    _sendKexDHGexInit();
  }

  void _handleMessageNewKeys(Uint8List message) {
    printDebug?.call('SSHTransport._handleMessageNewKeys');
    printTrace?.call('<- $socket: SSH_Message_NewKeys');
    _applyRemoteKeys();
  }
}
