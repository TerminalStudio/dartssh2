import 'dart:collection';

import 'package:dartssh2/src/http/http_exception.dart';
import 'package:dartssh2/src/http/http_headers.dart';

/// A MIME/IANA media type used as the value of the
/// [SSHHttpHeaders.contentTypeHeader] header.
///
/// A [SSHContentType] is immutable.
abstract class SSHContentType {
  /// Content type for plain text using UTF-8 encoding.
  ///
  ///     text/plain; charset=utf-8
  static final text = SSHContentType("text", "plain", charset: "utf-8");

  /// Content type for HTML using UTF-8 encoding.
  ///
  ///    text/html; charset=utf-8
  static final html = SSHContentType("text", "html", charset: "utf-8");

  /// Content type for JSON using UTF-8 encoding.
  ///
  ///    application/json; charset=utf-8
  static final json = SSHContentType("application", "json", charset: "utf-8");

  /// Content type for binary data.
  ///
  ///    application/octet-stream
  static final binary = SSHContentType("application", "octet-stream");

  /// Creates a new content type object setting the primary type and
  /// sub type. The charset and additional parameters can also be set
  /// using [charset] and [parameters]. If charset is passed and
  /// [parameters] contains charset as well the passed [charset] will
  /// override the value in parameters. Keys passed in parameters will be
  /// converted to lower case. The `charset` entry, whether passed as `charset`
  /// or in `parameters`, will have its value converted to lower-case.
  factory SSHContentType(
    String primaryType,
    String subType, {
    String? charset,
    Map<String, String?> parameters = const {},
  }) {
    return _ContentType(primaryType, subType, charset, parameters);
  }

  /// Creates a new content type object from parsing a Content-Type
  /// header value. As primary type, sub type and parameter names and
  /// values are not case sensitive all these values will be converted
  /// to lower case. Parsing this string
  ///
  ///     text/html; charset=utf-8
  ///
  /// will create a content type object with primary type "text",
  /// subtype "html" and parameter "charset" with value "utf-8".
  /// There may be more parameters supplied, but they are not recognized
  /// by this class.
  static SSHContentType parse(String value) {
    return _ContentType.parse(value);
  }

  /// Gets the MIME type and subtype, without any parameters.
  ///
  /// For the full content type `text/html;charset=utf-8`,
  /// the [mimeType] value is the string `text/html`.
  String get mimeType;

  /// Gets the primary type.
  ///
  /// For the full content type `text/html;charset=utf-8`,
  /// the [primaryType] value is the string `text`.
  String get primaryType;

  /// Gets the subtype.
  ///
  /// For the full content type `text/html;charset=utf-8`,
  /// the [subType] value is the string `html`.
  /// May be the empty string.
  String get subType;

  /// Gets the character set, if any.
  ///
  /// For the full content type `text/html;charset=utf-8`,
  /// the [charset] value is the string `utf-8`.
  String? get charset;
}

class _ContentType extends _HeaderValue implements SSHContentType {
  String _primaryType = "";
  String _subType = "";

  _ContentType(
    String primaryType,
    String subType,
    String? charset,
    Map<String, String?> parameters,
  )   : _primaryType = primaryType,
        _subType = subType,
        super("") {
    _value = "$_primaryType/$_subType";
    var parameterMap = _ensureParameters();
    parameters.forEach((String key, String? value) {
      String lowerCaseKey = key.toLowerCase();
      if (lowerCaseKey == "charset") {
        value = value?.toLowerCase();
      }
      parameterMap[lowerCaseKey] = value;
    });
    if (charset != null) {
      _ensureParameters()["charset"] = charset.toLowerCase();
    }
  }

  _ContentType._();

  static _ContentType parse(String value) {
    var result = _ContentType._();
    result._parse(value, ";", null, false);
    int index = result._value.indexOf("/");
    if (index == -1 || index == (result._value.length - 1)) {
      result._primaryType = result._value.trim().toLowerCase();
    } else {
      result._primaryType =
          result._value.substring(0, index).trim().toLowerCase();
      result._subType = result._value.substring(index + 1).trim().toLowerCase();
    }
    return result;
  }

  @override
  String get mimeType => '$primaryType/$subType';

  @override
  String get primaryType => _primaryType;

  @override
  String get subType => _subType;

  @override
  String? get charset => parameters["charset"];
}

class _HeaderValue {
  String _value;
  Map<String, String?>? _parameters;
  Map<String, String?>? _unmodifiableParameters;

  // ignore: unused_element
  _HeaderValue([this._value = "", Map<String, String?> parameters = const {}]) {
    if (parameters.isNotEmpty) {
      _parameters = HashMap<String, String?>.from(parameters);
    }
  }

  // ignore: unused_element
  static _HeaderValue parse(
    String value, {
    String parameterSeparator = ";",
    String? valueSeparator,
    bool preserveBackslash = false,
  }) {
    // Parse the string.
    var result = _HeaderValue();
    result._parse(value, parameterSeparator, valueSeparator, preserveBackslash);
    return result;
  }

  String get value => _value;

  Map<String, String?> _ensureParameters() =>
      _parameters ??= <String, String?>{};

  Map<String, String?> get parameters =>
      _unmodifiableParameters ??= UnmodifiableMapView(_ensureParameters());

  static bool _isToken(String token) {
    if (token.isEmpty) {
      return false;
    }
    final delimiters = "\"(),/:;<=>?@[]{}";
    for (int i = 0; i < token.length; i++) {
      int codeUnit = token.codeUnitAt(i);
      if (codeUnit <= 32 || codeUnit >= 127 || delimiters.contains(token[i])) {
        return false;
      }
    }
    return true;
  }

  @override
  String toString() {
    StringBuffer sb = StringBuffer();
    sb.write(_value);
    var parameters = _parameters;
    if (parameters != null && parameters.isNotEmpty) {
      parameters.forEach((String name, String? value) {
        sb
          ..write("; ")
          ..write(name);
        if (value != null) {
          sb.write("=");
          if (_isToken(value)) {
            sb.write(value);
          } else {
            sb.write('"');
            int start = 0;
            for (int i = 0; i < value.length; i++) {
              // Can use codeUnitAt here instead.
              int codeUnit = value.codeUnitAt(i);
              if (codeUnit == 92 /* backslash */ ||
                  codeUnit == 34 /* double quote */) {
                sb.write(value.substring(start, i));
                sb.write(r'\');
                start = i;
              }
            }
            sb
              ..write(value.substring(start))
              ..write('"');
          }
        }
      });
    }
    return sb.toString();
  }

  void _parse(
    String s,
    String parameterSeparator,
    String? valueSeparator,
    bool preserveBackslash,
  ) {
    int index = 0;

    bool done() => index == s.length;

    void skipWS() {
      while (!done()) {
        if (s[index] != " " && s[index] != "\t") return;
        index++;
      }
    }

    String parseValue() {
      int start = index;
      while (!done()) {
        var char = s[index];
        if (char == " " ||
            char == "\t" ||
            char == valueSeparator ||
            char == parameterSeparator) break;
        index++;
      }
      return s.substring(start, index);
    }

    void expect(String expected) {
      if (done() || s[index] != expected) {
        throw SSHHttpException("Failed to parse header value");
      }
      index++;
    }

    bool maybeExpect(String expected) {
      if (done() || !s.startsWith(expected, index)) {
        return false;
      }
      index++;
      return true;
    }

    void parseParameters() {
      var parameters = _ensureParameters();

      String parseParameterName() {
        int start = index;
        while (!done()) {
          var char = s[index];
          if (char == " " ||
              char == "\t" ||
              char == "=" ||
              char == parameterSeparator ||
              char == valueSeparator) break;
          index++;
        }
        return s.substring(start, index).toLowerCase();
      }

      String parseParameterValue() {
        if (!done() && s[index] == "\"") {
          // Parse quoted value.
          StringBuffer sb = StringBuffer();
          index++;
          while (!done()) {
            var char = s[index];
            if (char == "\\") {
              if (index + 1 == s.length) {
                throw SSHHttpException("Failed to parse header value");
              }
              if (preserveBackslash && s[index + 1] != "\"") {
                sb.write(char);
              }
              index++;
            } else if (char == "\"") {
              index++;
              return sb.toString();
            }
            char = s[index];
            sb.write(char);
            index++;
          }
          throw SSHHttpException("Failed to parse header value");
        } else {
          // Parse non-quoted value.
          return parseValue();
        }
      }

      while (!done()) {
        skipWS();
        if (done()) return;
        String name = parseParameterName();
        skipWS();
        if (maybeExpect("=")) {
          skipWS();
          String value = parseParameterValue();
          if (name == 'charset' && this is _ContentType) {
            // Charset parameter of ContentTypes are always lower-case.
            value = value.toLowerCase();
          }
          parameters[name] = value;
          skipWS();
        } else if (name.isNotEmpty) {
          parameters[name] = null;
        }
        if (done()) return;
        // !TODO: Implement support for multi-valued parameters.
        if (s[index] == valueSeparator) return;
        expect(parameterSeparator);
      }
    }

    skipWS();
    _value = parseValue();
    skipWS();
    if (done()) return;
    if (s[index] == valueSeparator) return;
    maybeExpect(parameterSeparator);
    parseParameters();
  }
}
