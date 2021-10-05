# DartSSH 2

[![pub package](https://img.shields.io/pub/v/dartssh2.svg)](https://pub.dartlang.org/packages/dartssh2) [![Build status](https://github.com/TerminalStudio/dartssh2/actions/workflows/dart.yml/badge.svg)](https://github.com/TerminalStudio/dartssh2/actions/workflows/dart.yml) [![Coverage Status](https://coveralls.io/repos/github/GreenAppers/dartssh/badge.svg?branch=master)](https://coveralls.io/github/GreenAppers/dartssh?branch=master) [![documentation](https://img.shields.io/badge/Documentation-dartssh2-blue.svg)](https://www.dartdocs.org/documentation/dartssh2/latest/)

`dartssh2`  is a pure dart SSH implementation based on [dartssh], with bug fixes, up-to-date dependencies and sound null safety.

`dartssh2` providing first-class tunnelling primitives.

## Feature support

|                            |                                 |
|----------------------------|---------------------------------|
| **Keys**                   | Ed25519, ECDSA, RSA             |
| **KEX**                    | X25519DH, ECDH, DHGEX, DH       |
| **Cipher**                 | AES-CTR, AES-CBC                |
| **MAC**                    | MD5, SHA                        |
| **Compression**            | not yet supported               |
| **Forwarding**             | TCP/IP, Agent                   |
| **Tunneling drop-ins** for | Socket, WebSocket, package:http |

## Try

```sh
# Install the `dartssh` command.
dart pub global activate dartssh2

# Then use `dartssh` as regular `ssh` command.
dartssh user@example.com
```

> If the `dartssh` command can not be found after installation, you might need to [set up your path](https://dart.dev/tools/pub/cmd/pub-global#running-a-script-from-your-path).

## Quick start - SSH client

<!-- CLIENT EXAMPLE BEGIN -->
<details >
<summary>
<sub><b>Click to see more:</b></sub>

```dart
import 'package:dartssh2/dartssh2.dart';
```
</summary>
<!-- <hr> -->
<h6>TODO</h6>

 ```html
TODO
```
</details>
<!-- CLIENT EXAMPLE END -->

## Quick start - SSH server

<!-- SERVER EXAMPLE BEGIN -->
<details >
<summary>
<sub><b>Click to see more:</b></sub>

```dart
import 'package:dartssh2/dartssh2.dart';
```
</summary>
<!-- <hr> -->
<h6>TODO</h6>

 ```html
TODO
```
</details>
<!-- SERVER EXAMPLE END -->


## Example

SSH client: [example/dartssh.dart](example/dartssh.dart)

SSH server: [example/dartsshs.dart](example/dartsshs.dart)

## Roadmap

- [x] Fix broken tests
- [x] Sound null safety
- [ ] Redesign API to allow starting multiple sessions. **In progress...**
- [ ] SFTP

## References

- [`RFC 4251`](https://datatracker.ietf.org/doc/html/rfc4251) The Secure Shell (SSH) Protocol Architecture
- [`RFC 4252`](https://datatracker.ietf.org/doc/html/rfc4252) The Secure Shell (SSH) Authentication Protocol
- [`RFC 4253`](https://datatracker.ietf.org/doc/html/rfc4253) The Secure Shell (SSH) Transport Layer Protocol
- [`RFC 4254`](https://datatracker.ietf.org/doc/html/rfc4254) The Secure Shell (SSH) Connection Protocol

## Credits

https://github.com/GreenAppers/dartssh by GreenAppers

## License

dartssh is released under the terms of the MIT license. See [LICENSE](LICENSE).

[dartssh]: https://github.com/GreenAppers/dartssh