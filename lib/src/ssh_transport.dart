import 'dart:async';
import 'dart:convert';
import 'dart:math' show Random, max;
import 'dart:typed_data';

import 'package:dartssh2/src/hostkey/hostkey_ecdsa.dart';
import 'package:dartssh2/src/hostkey/hostkey_rsa.dart';
import 'package:dartssh2/src/kex/kex_dh.dart';
import 'package:dartssh2/src/kex/kex_nist.dart';
import 'package:dartssh2/src/kex/kex_x25519.dart';
import 'package:dartssh2/src/ssh_algorithm.dart';
import 'package:dartssh2/src/ssh_kex.dart';
import 'package:dartssh2/src/utils/bigint.dart';
import 'package:dartssh2/src/utils/cipher_ext.dart';
import 'package:dartssh2/src/utils/chacha.dart';
import 'package:dartssh2/src/utils/chunk_buffer.dart';
import 'package:dartssh2/src/ssh_kex_utils.dart';
import 'package:dartssh2/src/ssh_packet.dart';
import 'package:dartssh2/src/utils/int.dart';
import 'package:dartssh2/src/hostkey/hostkey_ed25519.dart';
import 'package:dartssh2/src/message/base.dart';
import 'package:dartssh2/src/utils/list.dart';
import 'package:pointycastle/export.dart';

import '../dartssh2.dart';

typedef SSHPrintHandler = void Function(String?);

/// Function called when host key is received.
/// [type] is the type of the host key, for example 'ssh-rsa'.
/// [fingerprint] is the MD5 fingerprint of the host key. The SHA256
/// fingerprint is also logged via [printDebug] for user visibility.
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
  ///
  /// Security note: This callback is required for clients. If null, the
  /// transport rejects the connection by default rather than implicitly
  /// trusting the host key.
  final SSHHostkeyVerifyHandler? onVerifyHostKey;

  /// Function called when the transport is ready to send data.
  final SSHTransportReadyHandler? onReady;

  /// Function called when a packet is received.
  final SSHPacketHandler? onPacket;

  final bool disableHostkeyVerification;

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
    Duration reKeyInterval = const Duration(hours: 1),
    this.disableHostkeyVerification = false,
  }) : _reKeyInterval = reKeyInterval {
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

  /// Whether the transport ready callback has been dispatched.
  var _readyDispatched = false;

  /// Shared secret derived from the key exchange process. Kept to derive the
  /// cipher IV, cipher key and MAC key.
  BigInt? _sharedSecret;

  /// A [BlockCipher] to encrypt data sent to the other side.
  BlockCipher? _encryptCipher;

  /// A [BlockCipher] to decrypt data sent from the other side.
  BlockCipher? _decryptCipher;

  // AEAD (GCM / ChaCha20-Poly1305) keys and nonces (per direction)
  Uint8List? _localAeadKey; // key for data we send
  Uint8List?
      _localAeadFixedNonce; // 12-byte fixed part of nonce for data we send
  Uint8List? _remoteAeadKey; // key for data we receive
  Uint8List?
      _remoteAeadFixedNonce; // 12-byte fixed part of nonce for data we receive

  // OpenSSH chacha20-poly1305 uses two 32-byte keys per direction
  Uint8List?
      _localChaChaEncKey; // payload encryption / poly1305 one-time key generator
  Uint8List? _localChaChaLenKey; // length field encryption key
  Uint8List? _remoteChaChaEncKey; // payload decryption / poly1305 key generator
  Uint8List? _remoteChaChaLenKey; // length field decryption key

  Uint8List? _localCipherKey;

  Uint8List? _remoteCipherKey;

  Uint8List? _localIV;

  Uint8List? _remoteIV;

  /// A [Mac] used to authenticate data sent to the other side.
  Mac? _localMac;

  /// A [Mac] used to authenticate data sent from the other side.
  Mac? _remoteMac;

  final _localPacketSN = SSHPacketSN.fromZero();

  final _remotePacketSN = SSHPacketSN.fromZero();

  /// Whether a key exchange is currently in progress (initial or re-key).
  bool _kexInProgress = false;

  /// Whether we have already sent our SSH_MSG_KEXINIT for the ongoing key
  /// exchange round. This is reset when the exchange finishes.
  bool _sentKexInit = false;

  /// Packets queued during key exchange that will be sent after NEW_KEYS
  final List<Uint8List> _rekeyPendingPackets = [];

  Timer? _reKeyTimer;
  final Duration _reKeyInterval;
  var _bytesSent = 0;
  var _bytesReceived = 0;
  static const _dataLimitForRekey = 1024 * 1024 * 1024;

  void sendPacket(Uint8List data) {
    if (isClosed) {
      throw SSHStateError('Transport is closed');
    }

    if (_kexInProgress && !_shouldBypassRekeyBuffer(data)) {
      _rekeyPendingPackets.add(Uint8List.fromList(data));
      return;
    }

    final clientMacType = _clientMacType;
    final serverMacType = _serverMacType;
    final macType = isClient ? clientMacType : serverMacType;
    final localCipherType = isClient ? _clientCipherType : _serverCipherType;

    if (localCipherType != null &&
        localCipherType.isAead &&
        _localCipherKey != null &&
        _localIV != null) {
      _sendAeadPacket(data, localCipherType);
      _localPacketSN.increase();
      return;
    }

    final isEtm = _encryptCipher != null && macType != null && macType.isEtm;

    final ctLocal = isClient ? _clientCipherType : _serverCipherType;
    final usingAead = ctLocal?.isAead ?? false;
    final isChaCha = ctLocal?.name == 'chacha20-poly1305@openssh.com';
    final aeadReady = isChaCha
        ? (_localChaChaEncKey != null && _localChaChaLenKey != null)
        : (_localAeadKey != null && _localAeadFixedNonce != null);

    if (isEtm) {
      final blockSize = _encryptCipher!.blockSize;

      final paddingLength = blockSize - ((data.length + 1) % blockSize);
      // Ensure padding is at least 4 bytes as per SSH spec
      final adjustedPaddingLength =
          paddingLength < 4 ? paddingLength + blockSize : paddingLength;

      final packetLength = 1 + data.length + adjustedPaddingLength;

      final packetLengthBytes = Uint8List(4);
      packetLengthBytes.buffer.asByteData().setUint32(0, packetLength);

      final payloadToEncrypt = Uint8List(packetLength);
      payloadToEncrypt[0] = adjustedPaddingLength;
      payloadToEncrypt.setRange(1, 1 + data.length, data);

      final paddingBytes = randomBytes(adjustedPaddingLength);
      payloadToEncrypt.setRange(1 + data.length, packetLength, paddingBytes);

      // Verify that the payload length is a multiple of the block size
      assert(payloadToEncrypt.length % blockSize == 0,
          'Payload length ${payloadToEncrypt.length} is not a multiple of block size $blockSize');

      // Encrypt the payload
      final encryptedPayload = _encryptCipher!.processAll(payloadToEncrypt);

      final mac = _localMac!;
      mac.updateAll(_localPacketSN.value.toUint32());
      mac.updateAll(packetLengthBytes);
      mac.updateAll(encryptedPayload);
      final macBytes = mac.finish();

      final buffer = BytesBuilder(copy: false);
      buffer.add(packetLengthBytes);
      buffer.add(encryptedPayload);
      buffer.add(macBytes);

      _bytesSent +=
          packetLengthBytes.length + encryptedPayload.length + macBytes.length;

      socket.sink.add(buffer.takeBytes());
    } else if (usingAead && aeadReady) {
      final packetAlign = max(SSHPacket.minAlign, 8);
      final packet = SSHPacket.pack(data, align: packetAlign);

      final cipherType = isClient ? _clientCipherType! : _serverCipherType!;
      if (cipherType.name == 'chacha20-poly1305@openssh.com') {
        final encKey = _localChaChaEncKey;
        final lenKey = _localChaChaLenKey;
        if (encKey == null || lenKey == null) {
          throw StateError('ChaCha20-Poly1305 keys not initialized');
        }
        final out =
            _encryptChaChaOpenSSH(packet, encKey, lenKey, _localPacketSN.value);
        _bytesSent += packet.length + cipherType.aeadTagSize;
        socket.sink.add(out);
      } else {
        final key = _localAeadKey!;
        final fixedNonce = _localAeadFixedNonce!;

        final lenBytes = Uint8List.sublistView(packet, 0, 4);
        final body = Uint8List.sublistView(packet, 4);

        final nonce = _composeAeadNonce(fixedNonce, _localPacketSN.value);

        final aead = cipherType.createAEADCipher(
          key,
          nonce,
          forEncryption: true,
          aad: lenBytes,
        );

        final outLen = aead.getOutputSize(body.length);
        var encryptedWithTag = Uint8List(outLen);
        var written =
            aead.processBytes(body, 0, body.length, encryptedWithTag, 0);
        written += aead.doFinal(encryptedWithTag, written);
        if (written != encryptedWithTag.length) {
          encryptedWithTag =
              Uint8List.sublistView(encryptedWithTag, 0, written);
        }

        _bytesSent += packet.length + cipherType.aeadTagSize;

        final out = BytesBuilder(copy: false)
          ..add(lenBytes)
          ..add(encryptedWithTag);
        socket.sink.add(out.takeBytes());
      }
    } else if (_encryptCipher == null) {
      final packet = SSHPacket.pack(data, align: SSHPacket.minAlign);
      _bytesSent += packet.length;
      socket.sink.add(packet);
    } else {
      final packetAlign = max(SSHPacket.minAlign, _encryptCipher!.blockSize);
      final packet = SSHPacket.pack(data, align: packetAlign);

      final mac = _localMac!;
      final encryptedPacket = _encryptCipher!.processAll(packet);

      final buffer = BytesBuilder(copy: false);
      buffer.add(encryptedPacket);

      mac.updateAll(_localPacketSN.value.toUint32());
      mac.updateAll(packet);
      final macBytes = mac.finish();
      buffer.add(macBytes);

      _bytesSent += encryptedPacket.length + macBytes.length;

      socket.sink.add(buffer.takeBytes());
    }

    _localPacketSN.increase();

    if (_bytesSent >= _dataLimitForRekey) {
      _reKeyTimer?.cancel();
      _sendKexInit();
      _bytesSent = 0;
    }

    if (_encryptCipher != null && (Random().nextInt(10) == 0)) {
      _sendIgnoreMessageIfNeeded();
    }
  }

  void _sendAeadPacket(Uint8List data, SSHCipherType cipherType) {
    final paddingLength =
        _alignedPaddingLength(data.length, cipherType.blockSize);
    final packetLength = 1 + data.length + paddingLength;

    final aad = Uint8List(4)..buffer.asByteData().setUint32(0, packetLength);

    final plaintext = Uint8List(packetLength)
      ..[0] = paddingLength
      ..setRange(1, 1 + data.length, data);

    for (var i = 0; i < paddingLength; i++) {
      plaintext[1 + data.length + i] =
          (DateTime.now().microsecondsSinceEpoch + i) & 0xff;
    }

    final encrypted = _processAead(
      key: _localCipherKey!,
      iv: _localIV!,
      sequence: _localPacketSN.value,
      aad: aad,
      input: plaintext,
      forEncryption: true,
    );

    final buffer = BytesBuilder(copy: false)
      ..add(aad)
      ..add(encrypted);

    socket.sink.add(buffer.takeBytes());
  }

  int _alignedPaddingLength(int payloadLength, int align) {
    final paddingLength = align - ((payloadLength + 1) % align);
    return paddingLength < 4 ? paddingLength + align : paddingLength;
  }

  Uint8List _processAead({
    required Uint8List key,
    required Uint8List iv,
    required int sequence,
    required Uint8List aad,
    required Uint8List input,
    required bool forEncryption,
  }) {
    final cipher = GCMBlockCipher(AESEngine());
    final nonce = _nonceForSequence(iv, sequence);
    cipher.init(
      forEncryption,
      AEADParameters(KeyParameter(key), 128, nonce, aad),
    );
    return cipher.process(input);
  }

  Uint8List _nonceForSequence(Uint8List iv, int sequence) {
    if (iv.length != 12) {
      throw ArgumentError.value(iv, 'iv', 'AEAD IV must be 12 bytes long');
    }

    final nonce = Uint8List.fromList(iv);
    final view = ByteData.sublistView(nonce);
    final counter = view.getUint64(4);
    view.setUint64(4, counter + sequence);
    return nonce;
  }

  void close() {
    printDebug?.call('SSHTransport.close');
    if (isClosed) return;
    _socketSubscription?.cancel();
    _socketSubscription = null;
    _reKeyTimer?.cancel();
    _reKeyTimer = null;
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

    // Find the standard \r\n suffix
    var index = bufferString.indexOf('\r\n');
    if (index == -1) {
      // In the (rare) case SSH-2 version string is terminated by \n only (observed on Synology DS120j 2021)
      index = bufferString.indexOf('\n');
      if (index == -1) {
        return;
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

      /// For safety & performance reasons, we limit the maximum packet size.
      if (payload.length > SSHPacket.maxPayloadLength) {
        throw SSHPacketError('Packet too long: ${payload.length}');
      }

      _handleMessage(payload);

      _remotePacketSN.increase();
    }
  }

  /// Reads a single SSH packet from the buffer. Returns payload of the packet
  /// WITHOUT `packet length`, `padding length`, `padding` and `MAC`. Returns
  /// `null` if there is not enough data in the buffer to read the packet.
  Uint8List? _consumePacket() {
    final ct = isClient ? _serverCipherType : _clientCipherType;
    final usingAead = ct?.isAead ?? false;
    if (usingAead) {
      final isChaCha = ct?.name == 'chacha20-poly1305@openssh.com';
      final aeadReady = isChaCha
          ? (_remoteChaChaEncKey != null && _remoteChaChaLenKey != null)
          : (_remoteAeadKey != null && _remoteAeadFixedNonce != null);
      if (aeadReady) {
        return _consumeAeadPacket(ct!);
      }
    }
    return (_decryptCipher == null && _remoteCipherKey == null)
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

    final remoteCipherType = isClient ? _serverCipherType : _clientCipherType;
    if (remoteCipherType != null &&
        remoteCipherType.isAead &&
        _remoteCipherKey != null &&
        _remoteIV != null) {
      return _consumeAeadPacket(remoteCipherType);
    }

    final blockSize = _decryptCipher!.blockSize;
    if (_buffer.length < blockSize) {
      return null;
    }

    final macType = isClient ? _serverMacType! : _clientMacType!;
    final isEtm = macType.isEtm;
    final macLength = _remoteMac!.macSize;

    if (isEtm) {
      // For ETM (Encrypt-Then-MAC) algorithms, the packet length is in plaintext
      // followed by the encrypted payload and then the MAC

      // Read the packet length from the plaintext data
      final packetLength = SSHPacket.readPacketLength(_buffer.data);
      _verifyPacketLength(packetLength);

      // Make sure we have enough data for the entire packet and MAC
      if (_buffer.length < 4 + packetLength + macLength) {
        return null;
      }

      // Get the packet length bytes
      final packetLengthBytes = _buffer.view(0, 4);

      // Get the encrypted payload and MAC
      final encryptedPayload = _buffer.view(4, packetLength);
      final mac = _buffer.view(4 + packetLength, macLength);

      // Verify the MAC on the packet length and encrypted payload
      final packetForMac = Uint8List(4 + packetLength);
      packetForMac.setRange(0, 4, packetLengthBytes);
      packetForMac.setRange(4, 4 + packetLength, encryptedPayload);
      _verifyPacketMac(packetForMac, mac, isEncrypted: true);

      // Consume the packet and MAC from the buffer
      _buffer.consume(4 + packetLength + macLength);

      // Ensure the encrypted payload length is a multiple of the block size
      if (encryptedPayload.length % blockSize != 0) {
        throw SSHPacketError(
          'Encrypted payload length ${encryptedPayload.length} is not a multiple of block size $blockSize',
        );
      }

      // Decrypt the payload
      final decryptedPayload = _decryptCipher!.processAll(encryptedPayload);

      // Process the decrypted payload
      final paddingLength = decryptedPayload[0];

      // Verify that the padding length is valid
      if (paddingLength < 4) {
        throw SSHPacketError(
          'Padding length too small: $paddingLength (minimum is 4)',
        );
      }

      if (paddingLength >= packetLength) {
        throw SSHPacketError(
          'Padding length too large: $paddingLength (packet length is $packetLength)',
        );
      }

      final payloadLength = packetLength - paddingLength - 1;
      if (payloadLength < 0) {
        throw SSHPacketError(
          'Invalid payload length: $payloadLength (packet length: $packetLength, padding length: $paddingLength)',
        );
      }

      // Skip the padding length byte and extract the payload
      return Uint8List.sublistView(decryptedPayload, 1, 1 + payloadLength);
    } else {
      // For standard MAC algorithms, decrypt the packet first, then verify the MAC

      if (_decryptBuffer.isEmpty) {
        final firstBlock = _buffer.consume(blockSize);
        _decryptBuffer.add(_decryptCipher!.process(firstBlock));
      }

      final packetLength = SSHPacket.readPacketLength(_decryptBuffer.data);
      _verifyPacketLength(packetLength);

      if (_buffer.length + _decryptBuffer.length <
          4 + packetLength + macLength) {
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
      _verifyPacketMac(packet, mac, isEncrypted: false);

      return Uint8List.sublistView(packet, 5, packet.length - paddingLength);
    }
  }

  /// AEAD (GCM/ChaCha20-Poly1305) packet consumption.
  ///
  /// Layout:
  ///  - 4-byte packet length (plaintext, used as AAD)
  ///  - encrypted (padding_length + payload + padding)
  ///  - authentication tag (cipherType.aeadTagSize)
  Uint8List? _consumeAeadPacket(SSHCipherType cipherType) {
    printDebug?.call('SSHTransport._consumeAeadPacket');

    if (_buffer.length < 4) {
      return null;
    }

    if (cipherType.name == 'chacha20-poly1305@openssh.com') {
      return _consumeChaChaOpenSSHPacket();
    }

    final packetLength = SSHPacket.readPacketLength(_buffer.data);
    _verifyPacketLength(packetLength);

    final tagLength = cipherType.aeadTagSize;
    if (_buffer.length < 4 + packetLength + tagLength) {
      return null;
    }

    final aad = _buffer.consume(4);
    final ciphertext = _buffer.consume(packetLength);
    final tag = _buffer.consume(tagLength);

    final encryptedInput = Uint8List(packetLength + tagLength)
      ..setRange(0, packetLength, ciphertext)
      ..setRange(packetLength, packetLength + tagLength, tag);

    late Uint8List plaintext;
    try {
      plaintext = _processAead(
        key: _remoteAeadKey!,
        iv: _remoteAeadFixedNonce!,
        sequence: _remotePacketSN.value,
        aad: aad,
        input: encryptedInput,
        forEncryption: false,
      );
    } on InvalidCipherTextException {
      throw SSHPacketError('AEAD authentication failed');
    }

    final paddingLength = plaintext[0];
    final payloadLength = packetLength - paddingLength - 1;
    _verifyPacketPadding(payloadLength, paddingLength);
    return Uint8List.sublistView(plaintext, 1, 1 + payloadLength);
  }

  void _verifyPacketLength(int packetLength) {
    if (packetLength < 1 || packetLength > SSHPacket.maxLength) {
      throw SSHPacketError('Packet too long or invalid length: $packetLength');
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
  ///
  /// For ETM (Encrypt-Then-MAC) algorithms, the MAC is calculated on the packet length and encrypted payload.
  /// For standard MAC algorithms, the MAC is calculated on the unencrypted packet.
  void _verifyPacketMac(Uint8List payload, Uint8List actualMac,
      {bool isEncrypted = false}) {
    final macSize = _remoteMac!.macSize;
    if (actualMac.length != macSize) {
      throw SSHPacketError(
          'Invalid MAC size: ${actualMac.length}, expected: $macSize');
    }

    final macType = isClient ? _serverMacType! : _clientMacType!;
    final isEtm = macType.isEtm;

    _remoteMac!.updateAll(_remotePacketSN.value.toUint32());

    assert(isEtm == isEncrypted,
        'MAC algorithm mismatch: isEtm=$isEtm, isEncrypted=$isEncrypted');
    _remoteMac!.updateAll(payload);

    final expectedMac = _remoteMac!.finish();

    // Use constant time comparison to prevent timing attacks
    if (!constantTimeEquals(expectedMac, actualMac)) {
      throw SSHPacketError('MAC mismatch');
    }
  }

  /// Compares two byte arrays in constant time.
  bool constantTimeEquals(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    var result = 0;
    for (var i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result == 0;
  }

  void _startHandshake() {
    socket.sink.add(latin1.encode('$_localVersion\r\n'));

    if (isClient) {
      _sendKexInit();
    }
  }

  /// Encrypt packet using OpenSSH chacha20-poly1305 construction.
  /// Input [packet] is 4-byte length (plaintext) + body (padding_len|payload|padding).
  /// Output: enc_len(4) || enc_body || tag(16)
  Uint8List _encryptChaChaOpenSSH(
      Uint8List packet, Uint8List encKey, Uint8List lenKey, int seq) {
    // Split length and body
    final lenBytes = Uint8List.sublistView(packet, 0, 4);
    final body = Uint8List.sublistView(packet, 4);

    // Nonce per OpenSSH: 0x00000000 || uint64_le(seq) (upper 32 bits zero)
    final nonce = _composeChaChaNonce(seq);

    // 1) Encrypt 4-byte length using second key (counter=0)
    final encLen = Uint8List(4);
    final chachaLen = ChaCha7539Engine();
    chachaLen.init(true, ParametersWithIV(KeyParameter(lenKey), nonce));
    chachaLen.processBytes(lenBytes, 0, 4, encLen, 0);

    // 2) Derive one-time Poly1305 key from first 32 bytes of keystream (block 0)
    final chachaForPoly = ChaCha7539Engine();
    chachaForPoly.init(true, ParametersWithIV(KeyParameter(encKey), nonce));
    final polyBlock = Uint8List(64);
    chachaForPoly.processBytes(polyBlock, 0, 64, polyBlock, 0);
    final polyKey = Uint8List.sublistView(polyBlock, 0, 32);

    // 3) Encrypt body using chacha(encKey) starting from block 1
    final chachaPayload = ChaCha7539Engine();
    chachaPayload.init(true, ParametersWithIV(KeyParameter(encKey), nonce));
    if (body.isNotEmpty) {
      final discard = Uint8List(64); // advance one block
      chachaPayload.processBytes(discard, 0, 64, discard, 0);
    }
    final encBody = Uint8List(body.length);
    chachaPayload.processBytes(body, 0, body.length, encBody, 0);

    // 4) Poly1305 over: enc_len || pad16 || enc_body || pad16 || len(aad) LE64 || len(cipher) LE64
    final mac = Poly1305()..init(KeyParameter(polyKey));
    _poly1305UpdatePadded(mac, encLen);
    _poly1305UpdatePadded(mac, encBody);
    mac.updateAll(_le64(encLen.length));
    mac.updateAll(_le64(encBody.length));
    final tag = mac.finish();

    final out = BytesBuilder(copy: false)
      ..add(encLen)
      ..add(encBody)
      ..add(tag);
    return out.takeBytes();
  }

  /// Consume one OpenSSH chacha20-poly1305 packet from buffer.
  Uint8List? _consumeChaChaOpenSSHPacket() {
    // Need at least 4 bytes encrypted length
    if (_buffer.length < 4) return null;

    final encKey = _remoteChaChaEncKey;
    final lenKey = _remoteChaChaLenKey;
    if (encKey == null || lenKey == null) {
      throw StateError('ChaCha20-Poly1305 keys not initialized');
    }
    final nonce = _composeChaChaNonce(_remotePacketSN.value);

    // Poly1305 one-time key will be derived after reading enc_len + enc_body

    // Peek and decrypt 4-byte length
    final encLenBytes = _buffer.view(0, 4);
    final decLen = Uint8List(4);
    final chachaLen = ChaCha7539Engine();
    chachaLen.init(false, ParametersWithIV(KeyParameter(lenKey), nonce));
    chachaLen.processBytes(encLenBytes, 0, 4, decLen, 0);

    final len = SSHPacket.readPacketLength(decLen);
    _verifyPacketLength(len);

    final cipherType = isClient ? _serverCipherType! : _clientCipherType!;
    final tagSize = cipherType.aeadTagSize;
    final totalNeeded = 4 + len + tagSize;
    if (_buffer.length < totalNeeded) {
      return null;
    }

    // Now consume enc_len, enc_body, tag
    final encLen = _buffer.consume(4);
    final encBody = _buffer.consume(len);
    final tag = _buffer.consume(tagSize);

    // Derive one-time Poly1305 key (from block 0)
    final chachaForPoly = ChaCha7539Engine();
    chachaForPoly.init(false, ParametersWithIV(KeyParameter(encKey), nonce));
    final polyBlock = Uint8List(64);
    chachaForPoly.processBytes(polyBlock, 0, 64, polyBlock, 0);
    final polyKey = Uint8List.sublistView(polyBlock, 0, 32);

    // Verify MAC
    final mac = Poly1305()..init(KeyParameter(polyKey));
    _poly1305UpdatePadded(mac, encLen);
    _poly1305UpdatePadded(mac, encBody);
    mac.updateAll(_le64(encLen.length));
    mac.updateAll(_le64(encBody.length));
    final expectedTag = mac.finish();
    if (!constantTimeEquals(expectedTag, tag)) {
      throw SSHPacketError('AEAD decrypt/authentication failed: tag mismatch');
    }

    // Decrypt body using chacha(encKey) starting from block 1
    final chachaPayload = ChaCha7539Engine();
    chachaPayload.init(false, ParametersWithIV(KeyParameter(encKey), nonce));
    if (encBody.isNotEmpty) {
      final discard = Uint8List(64);
      chachaPayload.processBytes(discard, 0, 64, discard, 0);
    }
    final out = Uint8List(encBody.length);
    chachaPayload.processBytes(encBody, 0, encBody.length, out, 0);

    // out = [padding_length | payload | padding]
    if (out.isEmpty) {
      throw SSHPacketError('AEAD decrypted empty packet body');
    }

    final paddingLength = ByteData.sublistView(out).getUint8(0);
    final payloadLength = len - paddingLength - 1;
    _verifyPacketPadding(payloadLength, paddingLength);
    return Uint8List.sublistView(out, 1, 1 + payloadLength);
  }

  // RFC 7539-style Poly1305 block processing with 16-byte padding
  void _poly1305UpdatePadded(Mac mac, Uint8List data) {
    if (data.isNotEmpty) {
      mac.updateAll(data);
      final rem = data.length & 0x0f;
      if (rem != 0) {
        mac.updateAll(Uint8List(16 - rem));
      }
    }
  }

  // little-endian 64-bit length encoding (low 32-bit used)
  Uint8List _le64(int n) {
    final out = Uint8List(8);
    out[0] = n & 0xff;
    out[1] = (n >>> 8) & 0xff;
    out[2] = (n >>> 16) & 0xff;
    out[3] = (n >>> 24) & 0xff;
    // high 32 bits zero
    return out;
  }

  // OpenSSH chacha nonce: 0x00000000 || uint64_le(seq) where upper 32 bits are zero
  Uint8List _composeChaChaNonce(int seq) {
    final nonce = Uint8List(12);
    // bytes[0..3] = 0x00000000
    // bytes[4..7] = seq (little-endian)
    nonce[4] = (seq) & 0xff;
    nonce[5] = (seq >>> 8) & 0xff;
    nonce[6] = (seq >>> 16) & 0xff;
    nonce[7] = (seq >>> 24) & 0xff;
    // bytes[8..11] remain zero (upper 32 bits)
    return nonce;
  }

  void _applyLocalKeys() {
    final cipherType = isClient ? _clientCipherType : _serverCipherType;
    if (cipherType == null) throw StateError('No cipher type selected');

    if (cipherType.isAead) {
      if (cipherType.name == 'chacha20-poly1305@openssh.com') {
        // OpenSSH Chacha20-Poly1305 derives 64 bytes per direction.
        final rawKey = _deriveKey(
          isClient ? SSHDeriveKeyType.clientKey : SSHDeriveKeyType.serverKey,
          64,
        );
        final (lenKey: lenKey, encKey: encKey) = splitOpenSSHChaChaKeys(rawKey);
        _localChaChaLenKey = lenKey;
        _localChaChaEncKey = encKey;
        _localAeadKey = null;
        _localAeadFixedNonce = null;
      } else {
        // AEAD: derive key and fixed nonce (12 bytes) for sender direction
        final key = _deriveKey(
          isClient ? SSHDeriveKeyType.clientKey : SSHDeriveKeyType.serverKey,
          cipherType.keySize,
        );
        final iv = _deriveKey(
          isClient ? SSHDeriveKeyType.clientIV : SSHDeriveKeyType.serverIV,
          cipherType.ivSize,
        );
        _localAeadKey = key;
        _localAeadFixedNonce = Uint8List.sublistView(iv, 0, 12);
      }
      _encryptCipher = null;
      _localMac = null; // AEAD provides integrity
    } else {
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
        isClient
            ? SSHDeriveKeyType.clientMacKey
            : SSHDeriveKeyType.serverMacKey,
        macType.keySize,
      );

      _localMac = macType.createMac(macKey);
    }
  }

  void _applyRemoteKeys() {
    final cipherType = isClient ? _serverCipherType : _clientCipherType;
    if (cipherType == null) throw StateError('No cipher type selected');

    if (cipherType.isAead) {
      if (cipherType.name == 'chacha20-poly1305@openssh.com') {
        // Derive 64 bytes per direction and split according to OpenSSH spec.
        final rawKey = _deriveKey(
          isClient ? SSHDeriveKeyType.serverKey : SSHDeriveKeyType.clientKey,
          64,
        );
        final (lenKey: lenKey, encKey: encKey) = splitOpenSSHChaChaKeys(rawKey);
        _remoteChaChaLenKey = lenKey;
        _remoteChaChaEncKey = encKey;
        _remoteAeadKey = null;
        _remoteAeadFixedNonce = null;
      } else {
        final key = _deriveKey(
          isClient ? SSHDeriveKeyType.serverKey : SSHDeriveKeyType.clientKey,
          cipherType.keySize,
        );
        final iv = _deriveKey(
          isClient ? SSHDeriveKeyType.serverIV : SSHDeriveKeyType.clientIV,
          cipherType.ivSize,
        );
        _remoteAeadKey = key;
        _remoteAeadFixedNonce = Uint8List.sublistView(iv, 0, 12);
      }
      _decryptCipher = null;
      _remoteMac = null; // AEAD provides integrity
    } else {
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
        isClient
            ? SSHDeriveKeyType.serverMacKey
            : SSHDeriveKeyType.clientMacKey,
        macType.keySize,
      );
      _remoteMac = macType.createMac(macKey);
    }
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
    if (_sessionId == null) {
      throw StateError('Session ID not available, key exchange not completed');
    }

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

  /// Composes challenge data for host-based authentication according to RFC 4252
  ///
  /// The signature data MUST be constructed in the exact order specified by RFC 4252:
  /// - session identifier
  /// - SSH_MSG_USERAUTH_REQUEST byte
  /// - user name
  /// - service name
  /// - "hostbased" method name
  /// - public key algorithm for host key
  /// - public host key and certificates for client host
  /// - client host name (FQDN in US-ASCII)
  /// - user name on the client host (UTF-8 encoding)
  Uint8List composeHostbasedChallenge({
    required String username,
    required String service,
    required String publicKeyAlgorithm,
    required Uint8List publicKey,
    required String hostName,
    required String userNameOnClientHost,
  }) {
    if (_sessionId == null) {
      throw StateError('Session ID not available, key exchange not completed');
    }

    // RFC 4252: Validate inputs
    if (username.isEmpty) {
      throw ArgumentError('Username cannot be empty');
    }
    if (service.isEmpty) {
      throw ArgumentError('Service name cannot be empty');
    }
    if (publicKeyAlgorithm.isEmpty) {
      throw ArgumentError('Public key algorithm cannot be empty');
    }
    if (publicKey.isEmpty) {
      throw ArgumentError('Public key cannot be empty');
    }
    if (hostName.isEmpty) {
      throw ArgumentError('Host name cannot be empty');
    }
    if (userNameOnClientHost.isEmpty) {
      throw ArgumentError('User name on client host cannot be empty');
    }

    // Validate hostname is ASCII (RFC 4252 requirement)
    if (!_isAscii(hostName)) {
      throw ArgumentError('Host name must be in US-ASCII encoding');
    }

    // Validate username on client host can be encoded as UTF-8
    try {
      utf8.encode(userNameOnClientHost);
    } catch (e) {
      throw ArgumentError('User name on client host must be valid UTF-8: $e');
    }

    final writer = SSHMessageWriter();

    // RFC 4252: Signature data construction in exact order
    writer.writeString(_sessionId!); // session identifier
    writer.writeUint8(
        SSH_Message_Userauth_Request.messageId); // SSH_MSG_USERAUTH_REQUEST
    writer.writeUtf8(username); // user name
    writer.writeUtf8(service); // service name
    writer.writeUtf8('hostbased'); // method name
    writer.writeUtf8(publicKeyAlgorithm); // public key algorithm for host key
    writer.writeString(publicKey); // public host key and certificates
    writer.writeUtf8(hostName); // client host name (FQDN in US-ASCII)
    writer.writeUtf8(userNameOnClientHost); // user name on client host (UTF-8)

    return writer.takeBytes();
  }

  /// Check if string contains only ASCII characters
  bool _isAscii(String str) {
    for (int i = 0; i < str.length; i++) {
      if (str.codeUnitAt(i) > 127) {
        return false;
      }
    }
    return true;
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

    // Don't start a new key exchange when one is already in progress
    if (_kexInProgress && _sentKexInit) {
      printDebug?.call('Key exchange already in progress, ignoring');
      return;
    }

    // Mark that a new key-exchange round has started from our side.
    _kexInProgress = true;
    _sentKexInit = true;

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

  /// RFC 4251 Section 9.3.1
  void _sendIgnoreMessageIfNeeded() {
    if (isClosed) return;
    if (_encryptCipher == null) return;

    // Check if the cipher is a CBC mode cipher
    final cipherName = _clientCipherType?.name ?? _serverCipherType?.name;
    if (cipherName == null || !cipherName.endsWith('-cbc')) return;

    // Generate random data
    final length = 4 + (secureRandom.nextUint8()) % 12;
    final data = randomBytes(length);

    final message = SSH_Message_Ignore(data);
    printTrace?.call('-> $socket: $message [CBC padding]');
    sendPacket(message.encode());
  }

  void _handleMessage(Uint8List message) {
    _bytesReceived += message.length;

    // Check if we need to rekey
    if (_bytesReceived >= _dataLimitForRekey) {
      _reKeyTimer?.cancel();
      _sendKexInit();
      _bytesReceived = 0;
    }

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

    // If this message initiates a new key-exchange round from the remote
    // side, we MUST respond with our own KEXINIT (RFC 4253 §7.1).
    if (!_kexInProgress) {
      // Start a new exchange initiated by the peer.
      _kexInProgress = true;
    }

    if (!_sentKexInit) {
      // We have not sent our KEXINIT for this round yet, do it now.
      _sendKexInit();
    }

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
    if (_clientMacType == null && !_clientCipherType!.isAead) {
      throw StateError('No matching client MAC algorithm');
    }
    if (_serverMacType == null && !_serverCipherType!.isAead) {
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
      case SSHKexType.dh16Sha512:
        _kex = SSHKexDH.group16();
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

    if (!disableHostkeyVerification) {
      final verified = _verifyHostkey(
        keyBytes: hostkey,
        signatureBytes: hostSignature,
        exchangeHash: exchangeHash,
      );

      if (!verified) {
        throw SSHHostkeyError('Signature verification failed');
      }
    } else {
      _hostkeyVerified = true;
    }

    _exchangeHash = exchangeHash;
    _sessionId ??= exchangeHash;
    _sharedSecret = sharedSecret;

    if (_hostkeyVerified) {
      _sendNewKeys();
      _applyLocalKeys();
      if (!_readyDispatched) {
        _readyDispatched = true;
        onReady?.call();
      }
      return;
    }

    // Compute MD5 and SHA256 fingerprints of the received host key.
    final fingerprint = MD5Digest().process(hostkey);
    final fingerprintSha256 = SHA256Digest().process(hostkey);

    final fingerprintHex =
        fingerprint.map((b) => b.toRadixString(16).padLeft(2, '0')).join(':');
    final fingerprintSha256Base64 =
        base64.encode(fingerprintSha256).replaceAll('=', '');

    // RFC 4251 Section 4.1: Implementations SHOULD try to make best effort to check host keys
    // Log both modern SHA256 (base64) and legacy MD5 (hex with colons) fingerprints.
    printDebug?.call(
        'Server host key fingerprint: SHA256:$fingerprintSha256Base64 (MD5:$fingerprintHex) (${_hostkeyType?.name})');

    final verificationFuture = Future.sync(() async {
      final handler = onVerifyHostKey;
      if (handler == null) {
        printDebug?.call(
            'Host key verification handler not provided: rejecting by default');
        return false;
      }

      final result = await handler(_hostkeyType!.name, fingerprint);
      return result;
    });

    verificationFuture.then(
      (verified) {
        if (!verified) {
          closeWithError(
              SSHHostkeyError('Hostkey verification failed by user'));
        } else {
          _hostkeyVerified = true;
          _sendNewKeys();
          _applyLocalKeys();
          if (!_readyDispatched) {
            _readyDispatched = true;
            onReady?.call();
          }
        }
      },
      onError: (error, stack) {
        printDebug?.call('Error in host key verification: $error\n$stack');
        closeWithError(
            error is SSHError ? error : SSHInternalError(error), stack);
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

    // Key exchange round finished.
    _kexInProgress = false;
    _sentKexInit = false;
    _kex = null;

    // Flush any pending packets
    final pending = List<Uint8List>.from(_rekeyPendingPackets);
    _rekeyPendingPackets.clear();
    for (final packet in pending) {
      sendPacket(packet);
    }

    // Reset the rekey timer.
    _reKeyTimer?.cancel();
    _reKeyTimer = Timer(_reKeyInterval, () {
      if (!isClosed) {
        _sendKexInit();
      }
    });
  }

  /// Returns true if both encryption ciphers are initialized (confidentiality is provided).
  bool get hasConfidentiality {
    final aeadReadyGcm = _localAeadKey != null && _remoteAeadKey != null;
    final aeadReadyChaCha = _localChaChaEncKey != null &&
        _localChaChaLenKey != null &&
        _remoteChaChaEncKey != null &&
        _remoteChaChaLenKey != null;
    return aeadReadyGcm ||
        aeadReadyChaCha ||
        (_encryptCipher != null && _decryptCipher != null);
  }

  /// Returns true if both MACs are initialized (MAC protection is provided).
  bool get hasMacProtection {
    final usingAead = (_clientCipherType?.isAead == true) ||
        (_serverCipherType?.isAead == true);
    if (usingAead) return true;
    return _localMac != null && _remoteMac != null;
  }

  /// Compose 12-byte AEAD nonce from 8-byte fixed IV and 32-bit sequence number.
  Uint8List _composeAeadNonce(Uint8List fixed, int seq) {
    if (fixed.length < 12) {
      throw StateError('AEAD fixed nonce must be at least 12 bytes');
    }
    final nonce = Uint8List(12);
    nonce[0] = (seq >>> 24) & 0xff;
    nonce[1] = (seq >>> 16) & 0xff;
    nonce[2] = (seq >>> 8) & 0xff;
    nonce[3] = (seq) & 0xff;
    nonce.setRange(4, 12, fixed);
    return nonce;
  }

  /// Initiates a client-side re-key operation. This can be called
  /// by client code to refresh session keys when needed.
  void rekey() {
    printDebug?.call('SSHTransport.rekey');
    if (_kexInProgress) {
      printDebug
          ?.call('Key exchange already in progress, ignoring rekey request');
      return;
    }
    _sendKexInit();
  }

  /// Determines if a packet should bypass the rekey buffer.
  ///
  /// During key exchange, most packets should be buffered until the exchange
  /// is complete. However, key exchange packets themselves and transport layer
  /// control messages (like disconnect) need to be sent immediately.
  ///
  /// Per RFC 4253, the following message types bypass the buffer:
  ///
  /// Critical transport messages (1-4):
  /// - 1: [SSH_Message_Disconnect]
  /// - 2: [SSH_Message_Ignore]
  /// - 3: [SSH_Message_Unimplemented]
  /// - 4: [SSH_Message_Debug]
  ///
  /// Key exchange messages (20-49):
  /// - 20: [SSH_Message_KexInit]
  /// - 21: [SSH_Message_NewKeys]
  /// - 30: [SSH_Message_KexDH_Init]/[SSH_Message_KexECDH_Init]
  /// - 31: [SSH_Message_KexDH_Reply]/[SSH_Message_KexECDH_Reply]/[SSH_Message_KexDH_GexGroup]
  /// - 32: [SSH_Message_KexDH_GexInit]
  /// - 33: [SSH_Message_KexDH_GexReply]
  /// - 34: [SSH_Message_KexDH_GexRequest]
  bool _shouldBypassRekeyBuffer(Uint8List data) {
    if (data.isEmpty) return false;

    final messageId = data[0];
    return (messageId >= 20 && messageId <= 49) ||
        (messageId >= 1 && messageId <= 4);
  }
}
