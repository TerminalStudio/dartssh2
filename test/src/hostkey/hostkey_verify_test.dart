import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/hostkey/hostkey_ecdsa.dart';
import 'package:dartssh2/src/hostkey/hostkey_rsa.dart';
import 'package:test/test.dart';

import '../../test_utils.dart';

/// Signs with the private half of a fixture key and verifies with the public
/// half, which is the path the transport takes for every host key signature.
void main() {
  final message = Uint8List.fromList(
    List.generate(64, (index) => (index * 7) % 256),
  );

  group('SSHRsaPublicKey.verify', () {
    late OpenSSHRsaKeyPair keyPair;
    late SSHRsaPublicKey publicKey;

    setUp(() {
      keyPair = SSHKeyPair.fromPem(fixture('ssh-rsa/id_rsa.openssh')).single
          as OpenSSHRsaKeyPair;
      publicKey = keyPair.toPublicKey() as SSHRsaPublicKey;
    });

    test('accepts a genuine rsa-sha2-256 signature', () {
      final signature = keyPair.sign(message);

      expect(signature.type, SSHRsaSignatureType.sha256);
      expect(publicKey.verify(message, signature), isTrue);
    });

    test('rejects a signature over different data', () {
      final signature = keyPair.sign(message);
      final otherMessage = Uint8List.fromList(message)..[0] ^= 0xff;

      expect(publicKey.verify(otherMessage, signature), isFalse);
    });

    test('rejects a tampered signature', () {
      final signature = keyPair.sign(message);
      final tampered = SSHRsaSignature(
        signature.type,
        Uint8List.fromList(signature.signature)..[0] ^= 0x01,
      );

      expect(publicKey.verify(message, tampered), isFalse);
    });

    test('rejects a signature verified under the wrong hash', () {
      // Relabelling an rsa-sha2-256 signature as SHA-1 or SHA-512 must not
      // verify: the digest OID is part of what is signed.
      final signature = keyPair.sign(message);

      for (final type in [
        SSHRsaSignatureType.sha1,
        SSHRsaSignatureType.sha512,
      ]) {
        final relabelled = SSHRsaSignature(type, signature.signature);
        expect(publicKey.verify(message, relabelled), isFalse);
      }
    });

    test('throws on an unknown signature type', () {
      final signature = SSHRsaSignature('rsa-sha2-999', Uint8List(32));

      expect(
        () => publicKey.verify(message, signature),
        throwsA(isA<FormatException>()),
      );
    });

    test('encodes and decodes the public key', () {
      final decoded = SSHRsaPublicKey.decode(publicKey.encode());

      expect(decoded.e, publicKey.e);
      expect(decoded.n, publicKey.n);
      expect(decoded.toString(), contains('SSHRsaKey'));
    });

    test('decode rejects a key of the wrong type', () {
      final wrongType = SSHEcdsaPublicKey(
        type: 'ecdsa-sha2-nistp256',
        curveId: 'nistp256',
        q: Uint8List(1),
      ).encode();

      expect(() => SSHRsaPublicKey.decode(wrongType), throwsException);
    });

    test('signature encodes and decodes', () {
      final signature = keyPair.sign(message);
      final decoded = SSHRsaSignature.decode(signature.encode());

      expect(decoded.type, signature.type);
      expect(decoded.signature, signature.signature);
      expect(decoded.toString(), contains('SSHRsaSignature'));
    });
  });

  group('SSHEcdsaPublicKey.verify', () {
    for (final curve in ['nistp256', 'nistp384', 'nistp521']) {
      group(curve, () {
        late OpenSSHEcdsaKeyPair keyPair;
        late SSHEcdsaPublicKey publicKey;

        setUp(() {
          keyPair = SSHKeyPair.fromPem(fixture('ecdsa-sha2-$curve/id_ecdsa'))
              .single as OpenSSHEcdsaKeyPair;
          publicKey = keyPair.toPublicKey() as SSHEcdsaPublicKey;
        });

        test('accepts a genuine signature', () {
          final signature = keyPair.sign(message);

          expect(signature.type, 'ecdsa-sha2-$curve');
          expect(publicKey.verify(message, signature), isTrue);
        });

        test('rejects a signature over different data', () {
          final signature = keyPair.sign(message);
          final otherMessage = Uint8List.fromList(message)..[1] ^= 0xff;

          expect(publicKey.verify(otherMessage, signature), isFalse);
        });

        test('rejects a signature with a mangled scalar', () {
          final signature = keyPair.sign(message);
          final mangled = SSHEcdsaSignature(
            signature.type,
            signature.r + BigInt.one,
            signature.s,
          );

          expect(publicKey.verify(message, mangled), isFalse);
        });

        test('signature encodes and decodes', () {
          final signature = keyPair.sign(message);
          final decoded = SSHEcdsaSignature.decode(signature.encode());

          expect(decoded.type, signature.type);
          expect(decoded.r, signature.r);
          expect(decoded.s, signature.s);
          expect(decoded.toString(), contains(curve));
        });

        test('public key encodes and decodes', () {
          final decoded = SSHEcdsaPublicKey.decode(publicKey.encode());

          expect(decoded.type, publicKey.type);
          expect(decoded.curveId, curve);
          expect(decoded.q, publicKey.q);
          expect(decoded.toString(), contains(curve));
        });

        test('selects the matching curve and hash', () {
          expect(publicKey.curve.domainName, isNotEmpty);
          expect(
            publicKey.curveHash.digestSize,
            {'nistp256': 32, 'nistp384': 48, 'nistp521': 64}[curve],
          );
        });
      });
    }

    test('decode rejects a key of the wrong type', () {
      final wrongType = SSHRsaPublicKey(BigInt.two, BigInt.from(9)).encode();

      expect(() => SSHEcdsaPublicKey.decode(wrongType), throwsException);
    });

    test('decode rejects a signature of the wrong type', () {
      final wrongType = SSHRsaSignature('ssh-rsa', Uint8List(4)).encode();

      expect(
        () => SSHEcdsaSignature.decode(wrongType),
        throwsA(isA<FormatException>()),
      );
    });

    test('throws on an unsupported curve', () {
      final key = SSHEcdsaPublicKey(
        type: 'ecdsa-sha2-nistp192',
        curveId: 'nistp192',
        q: Uint8List(1),
      );

      expect(() => key.curve, throwsException);
      expect(() => key.curveHash, throwsException);
    });
  });
}
