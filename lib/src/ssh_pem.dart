import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

class SSHPem {
  final String type;

  final Uint8List content;

  SSHPem(this.type, this.content);

  static const _pemHeaderBegin = '-----BEGIN ';
  static const _pemFooterBegin = '-----END ';
  static const _pemEnd = '-----';

  factory SSHPem.decode(String pem) {
    final lines = pem.trim().split("\n");
    final header = lines.first;
    final footer = lines.last;

    if (!header.startsWith(_pemHeaderBegin)) {
      throw FormatException('PEM header must start with $_pemHeaderBegin');
    }
    if (!footer.startsWith(_pemFooterBegin)) {
      throw FormatException('PEM footer must start with $_pemFooterBegin');
    }
    if (!header.endsWith(_pemEnd)) {
      throw FormatException('PEM header must end with $_pemEnd');
    }
    if (!footer.endsWith(_pemEnd)) {
      throw FormatException('PEM footer must end with $_pemEnd');
    }

    final type = header.substring(
      _pemHeaderBegin.length,
      header.length - _pemEnd.length,
    );
    final footerType = footer.substring(
      _pemFooterBegin.length,
      footer.length - _pemEnd.length,
    );

    if (type != footerType) {
      throw FormatException('Type mismatch: $type != $footerType');
    }

    final contentBase64 =
        lines.sublist(1, lines.length - 1).map((line) => line.trim()).join('');

    final content = base64.decode(contentBase64);
    return SSHPem(type, content);
  }

  String encode([int lineLength = 64]) {
    final encoded = base64.encode(content);
    final builder = StringBuffer();
    builder.writeln('-----BEGIN $type-----');
    for (var i = 0; i < encoded.length; i += lineLength) {
      final chunk = encoded.substring(i, min(i + lineLength, encoded.length));
      builder.writeln(chunk);
    }
    builder.writeln('-----END $type-----');
    return builder.toString();
  }

  @override
  String toString() {
    return '$runtimeType($type, length: ${content.length})';
  }
}
