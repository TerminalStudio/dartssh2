import 'package:dartssh2/dartssh2.dart';

class MockSSHHttpHeaders extends SSHHttpHeaders {
  final Map<String, List<String>> _headers = {};

  @override
  List<String>? operator [](String name) => _headers[name.toLowerCase()];

  @override
  String? value(String name) {
    final values = _headers[name.toLowerCase()];
    if (values != null && values.length == 1) {
      return values.first;
    }
    return null;
  }

  @override
  void add(String name, Object value, {bool preserveHeaderCase = false}) {
    final headerName = preserveHeaderCase ? name : name.toLowerCase();
    final valueStr =
        value is DateTime ? value.toIso8601String() : value.toString();
    _headers.putIfAbsent(headerName, () => []).add(valueStr);
  }

  @override
  void set(String name, Object value, {bool preserveHeaderCase = false}) {
    final headerName = preserveHeaderCase ? name : name.toLowerCase();
    final valueStr =
        value is DateTime ? value.toIso8601String() : value.toString();
    _headers[headerName] = [valueStr];
  }

  @override
  void remove(String name, Object value) {
    final values = _headers[name.toLowerCase()];
    values?.remove(value.toString());
    if (values != null && values.isEmpty) {
      _headers.remove(name.toLowerCase());
    }
  }

  @override
  void removeAll(String name) {
    _headers.remove(name.toLowerCase());
  }

  @override
  void forEach(void Function(String name, List<String> values) action) {
    _headers.forEach(action);
  }

  @override
  void noFolding(String name) {
    // Implementar comportamiento de no fold
  }

  @override
  void clear() {
    _headers.clear();
  }
}
