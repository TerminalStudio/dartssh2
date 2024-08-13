## [3.0.0] - 2024-08-13

- Changed version constraints for package `pinenacl` from `^0.5.0` to `">=0.5.0 <1.0.0"` to support Dart SDK `>= 3.5.0`. See Dart SDK [Changelog](https://github.com/dart-lang/sdk/blob/3ccadc5c277a6c70f207d14600524578f4c527ad/CHANGELOG.md?plain=1#L106).

- Bumped SDK constraints from `">=2.17.0 <3.0.0"` up to `">=2.17.0 <4.0.0"`

- Bug fix in `SftpFileWriter` for [#50](https://github.com/TerminalStudio/dartssh2/issues/50), [#71](https://github.com/TerminalStudio/dartssh2/issues/71), [#100](https://github.com/TerminalStudio/dartssh2/issues/100):

  When the input stream contains only one event and that event has fewer bytes than `maxBytesOnTheWire`, then the `SftpFileWriter._doneCompleter` never got completed. This happened because the completer got only completed in the `_handleLocalData` event handler if the `_streamDone` flag was already true, the problem is that if the stream only has one small event, then `_handleLocalData` will only be called once with the event and afterward `_handleLocalDone` will be called once, which sets `_streamDone` to true. At this point the `_doneCompleter` cannot be completed anymore because the `_handleLocalData` will not get called anymore. This problem causes never ending `await` statements when opening and writing a file.

  This issue has been fixed by checking if all sent bytes have already been acknowledged in the `_handleLocalDone` event handler and subsequently completing the `_doneCompleter`.
  ```dart
    void _handleLocalDone() {
      _streamDone = true;
      if (_bytesSent == _bytesAcked) {
        _doneCompleter.complete();
      }
    }
  ```

- Added return type `SftpFileOpenMode` to operator `|` in class `SftpFileOpenMode`. Fix for [#80](https://github.com/TerminalStudio/dartssh2/issues/80).

## [2.9.1-pre] - 2023-04-02
- Make the type of `SSHForwardChannel.sink` to `StreamSink<List<int>>` to match
  its super class.
- Added `SSHHttpClient` for easy http request forwarding.

## [2.9.0-pre] - 2023-03-31
- Better handling of channel close.
- Make `SSHForwardChannel` implement `SSHSocket` for better interoperability.

## [2.8.2] - 2023-03-07
- Make `SftpFileWriter` implement `Future<void>` for backward compatibility.

## [2.8.1] - 2023-03-07
- Export `SftpFileWriter`

## [2.8.0] - 2023-03-06
- `SftpFile.write` now returns a `SftpFileWriter` that can be used to control
  the writing process.
- Support `SftpClient.statvfs` and `SftpFile.statvfs`.
- Support automatic keepalive.

## 2.7.3
- Update README.md
- Move cli into separate package.
- Properly handle chunk read error during stream read.

## 2.7.2+3
- Update README.md

## 2.7.2+2
- Update README.md

## 2.7.2+1
- Update README.md

## 2.7.2
- Upgrade `pinenacl` to `0.5.0`.
- Fix bug in exporting openssh private key to pem, thanks [@PIDAMI]

## 2.7.1
- Upgrade rsa authentication algorithm to rsa-sha2-256.

## 2.7.0
- Support encrypted RSA format private key

## 2.6.1
- Allow username with `@` in `dartssh2` command [#24]

## 2.6.0
- Allow ignoring stdout or stderr in `SSHClient.run`.
- Add `SSHAuthFailError` and `SSHAuthAbortError`.
- Fix file type detection.
- Fix empty identity handling [#21]
- Add connection reset handing.
- Add more tests

## 2.5.0
- Fix js import path [#18].
- Ignore remote data after channel closed.

## 2.4.4
- Fix lint errors

## 2.4.3
- Remove unused dependencies
- Fix lint errors

## 2.4.2
- Fix null check error in `kill()` [#17]
- More examples in README.md
## 2.4.1
- More examples in README.md
- Limit the maximum size of channel packets

## 2.4.0
- Support session stdin streaming and EOF

## 2.3.1
- Support ssh v2 when version string does not contain CR [#14], thanks [@Migarl]

## 2.3.1-pre
- Add remoteVersion field to SSHClient

## 2.3.0-pre
- Add description field in SSHChannelOpenError

## 2.2.0
- Update README.md
- Support export keypair to PEM

## 2.1.0-pre
- Update README.md
- Support loading OpenSSH encrypted pem files.

## 2.0.0-pre
- Implements local port forwarding
- Implements remote port forwarding
- Implements SFTP client
- More supported algorithms
- Added `dartsftp` command

## 1.2.0-pre

- Rework login logic.
- `dartssh` command now supports login with public key.

## 1.1.4-pre

- `dartssh` command now supports terminal window resize.

## 1.1.3-pre

- Add `--verbose` option in `dartssh` command.

## 1.1.2-pre

- Fix typos.

## 1.1.1-pre

- Organize exports.
## 1.1.0-pre

- Dependency update.
- Sound null safety.
- Replace deprecated `pedantic` with `package:lints`
- Fix crash running vim by [@linhanyu].  [#1]

## 1.0.4+4

- Increase test coverage and documentation.

## 1.0.3+3

- Fix tunneled WebSocket issue.

## 1.0.2+2

- Add example/README.md

## 1.0.1+1

- Add SSHTunneledSocketImpl, SSHTunneledWebSocketImpl, and SSHTunneledBaseClient.

## 1.0.0+0

- Initial release.

[#24]: https://github.com/TerminalStudio/dartssh2/issues/24
[#21]: https://github.com/TerminalStudio/dartssh2/issues/21
[#18]: https://github.com/TerminalStudio/dartssh2/issues/18
[#17]: https://github.com/TerminalStudio/dartssh2/issues/17
[#14]: https://github.com/TerminalStudio/dartssh2/pull/14
[#1]: https://github.com/TerminalStudio/dartssh/pull/1/files

[@linhanyu]: https://github.com/linhanyu
[@Migarl]: https://github.com/Migarl
[@PIDAMI]: https://github.com/PIDAMI