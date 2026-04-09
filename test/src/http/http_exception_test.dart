import 'package:dartssh2/src/http/http_exception.dart';
import 'package:test/test.dart';

void main() {
  group('SSHHttpException', () {
    test('should store and return the message correctly', () {
      // Arrange
      final message = 'An error occurred';
      final exception = SSHHttpException(message);

      // Act
      final resultMessage = exception.message;

      // Assert
      expect(resultMessage, equals(message));
    });

    test('should store and return the URI correctly', () {
      // Arrange
      final message = 'An error occurred';
      final uri = Uri.parse('http://example.com/');
      final exception = SSHHttpException(message, uri: uri);

      // Act
      final resultUri = exception.uri;

      // Assert
      expect(resultUri, equals(uri));
    });

    test('should return correct string representation with URI', () {
      // Arrange
      final message = 'An error occurred';
      final uri = Uri.parse('http://example.com/');
      final exception = SSHHttpException(message, uri: uri);

      // Act
      final resultString = exception.toString();

      // Assert
      expect(
          resultString,
          equals(
              'SSHHttpException: An error occurred, uri = http://example.com/'));
    });

    test('should return correct string representation without URI', () {
      // Arrange
      final message = 'An error occurred';
      final exception = SSHHttpException(message);

      // Act
      final resultString = exception.toString();

      // Assert
      expect(resultString, equals('SSHHttpException: An error occurred'));
    });
  });
}
