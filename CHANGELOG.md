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

[#17]: https://github.com/TerminalStudio/dartssh2/issues/17
[#14]: https://github.com/TerminalStudio/dartssh2/pull/14
[#1]: https://github.com/TerminalStudio/dartssh/pull/1/files

[@linhanyu]: https://github.com/linhanyu
[@Migarl]: https://github.com/Migarl