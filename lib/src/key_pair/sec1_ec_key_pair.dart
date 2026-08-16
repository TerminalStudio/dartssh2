import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:dartssh2/src/key_pair/openssh_key_pair.dart';
import 'package:dartssh2/src/key_pair/pkcs1_rsa_key_pair.dart';
import 'package:dartssh2/src/ssh_errors.dart';
import 'package:dartssh2/src/ssh_pem.dart';
import 'package:dartssh2/src/utils/bigint.dart';
import 'package:dartssh2/src/utils/list.dart';
import 'package:pointycastle/export.dart';

/// Container for an elliptic curve private key in SEC1 ASN.1 format (`BEGIN EC PRIVATE KEY`).
class EcKeyPair {
  /// Header encryption metadata from PEM DEK-Info header, if encrypted.
  final RsaKeyPairDEKInfo? dekInfo;

  /// Raw bytes of the ASN.1 DER-encoded EC private key blob.
  final Uint8List keyBlob;

  /// Creates an [EcKeyPair] container with optional [dekInfo] and [keyBlob].
  const EcKeyPair(this.dekInfo, this.keyBlob);

  /// Decodes an [EcKeyPair] from a parsed [SSHPem] structure.
  factory EcKeyPair.decode(SSHPem pem) {
    final dekInfoHeader = pem.headers['DEK-Info'];

    final dekInfo =
        dekInfoHeader != null ? RsaKeyPairDEKInfo.parse(dekInfoHeader) : null;

    final keyBlob = pem.content;

    return EcKeyPair(dekInfo, keyBlob);
  }

  /// Whether the EC private key is encrypted with a passphrase.
  bool get isEncrypted => dekInfo != null;

  /// Decodes and returns the ECDSA key pair as an [OpenSSHEcdsaKeyPair].
  OpenSSHEcdsaKeyPair getPrivateKeys([String? passphrase]) {
    if (isEncrypted) {
      throw UnsupportedError(
        'Encrypted EC PRIVATE KEY is not supported yet',
      );
    }

    if (passphrase != null) {
      throw ArgumentError('Passphrase is not required for unencrypted keys');
    }

    try {
      return _decodeLegacyEcPrivateKey(keyBlob);
    } on UnsupportedError {
      rethrow;
    } catch (e) {
      throw SSHKeyDecodeError('Failed to decode private key', e);
    }
  }

  OpenSSHEcdsaKeyPair _decodeLegacyEcPrivateKey(Uint8List keyBlob) {
    final parser = ASN1Parser(keyBlob);
    final sequence = parser.nextObject() as ASN1Sequence;

    if (sequence.elements.length < 2) {
      throw FormatException('Invalid EC private key sequence');
    }

    final privateKeyOctets = (sequence.elements[1] as ASN1OctetString).octets;
    final d = decodeBigIntWithSign(1, privateKeyOctets);

    Uint8List? publicPoint;
    String? curveId;

    for (var i = 2; i < sequence.elements.length; i++) {
      final element = sequence.elements[i];
      if (element.tag == 0xA0) {
        final inner = ASN1Parser(element.valueBytes()).nextObject();
        if (inner is ASN1ObjectIdentifier && inner.identifier != null) {
          final oid = inner.identifier!;
          curveId = _curveIdFromOid(oid);
          if (curveId == null) {
            throw UnsupportedError(
                'Unsupported EC PRIVATE KEY curve OID: $oid');
          }
        }
      } else if (element.tag == 0xA1) {
        final inner = ASN1Parser(element.valueBytes()).nextObject();
        if (inner is ASN1BitString) {
          publicPoint = inner.contentBytes();
        }
      }
    }

    curveId ??=
        _inferCurveId(publicPoint?.length ?? 0, privateKeyOctets.length);
    if (curveId == null) {
      throw UnsupportedError('Unsupported EC PRIVATE KEY curve');
    }

    if (publicPoint != null) {
      final expectedPublicPoint = _derivePublicPoint(curveId, d);
      if (publicPoint.length != expectedPublicPoint.length ||
          !publicPoint.equals(expectedPublicPoint)) {
        throw UnsupportedError(
            'EC PRIVATE KEY public point does not match curve $curveId');
      }
    }

    final q = publicPoint ?? _derivePublicPoint(curveId, d);

    return OpenSSHEcdsaKeyPair(curveId, q, d, '');
  }

  String? _curveIdFromOid(String oid) {
    if (oid == '1.2.840.10045.3.1.7') return 'nistp256';
    if (oid == '1.3.132.0.34') return 'nistp384';
    if (oid == '1.3.132.0.35') return 'nistp521';
    return null;
  }

  String? _inferCurveId(int publicPointLength, int privateKeyLength) {
    if (publicPointLength == 65 || privateKeyLength == 32) {
      return 'nistp256';
    }
    if (publicPointLength == 97 || privateKeyLength == 48) {
      return 'nistp384';
    }
    if (publicPointLength == 133 || privateKeyLength == 66) {
      return 'nistp521';
    }
    return null;
  }

  Uint8List _derivePublicPoint(String curveId, BigInt d) {
    final curve = _curveForId(curveId);
    final point = curve.G * d;
    if (point == null) {
      throw FormatException('Failed to derive public EC point');
    }
    return point.getEncoded(false);
  }

  ECDomainParameters _curveForId(String curveId) {
    switch (curveId) {
      case 'nistp256':
        return ECCurve_secp256r1();
      case 'nistp384':
        return ECCurve_secp384r1();
      case 'nistp521':
        return ECCurve_secp521r1();
      default:
        throw UnsupportedError('Unsupported curve: $curveId');
    }
  }
}
