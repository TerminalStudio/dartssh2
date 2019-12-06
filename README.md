# dartssh [![pub package](https://img.shields.io/pub/v/dartssh.svg)](https://pub.dartlang.org/packages/dartssh) [![Build Status](https://travis-ci.org/GreenAppers/dartssh.svg?branch=master)](https://travis-ci.org/GreenAppers/dartssh) [![Coverage Status](https://coveralls.io/repos/github/GreenAppers/dartssh/badge.svg?branch=master)](https://coveralls.io/github/GreenAppers/dartssh?branch=master) [![documentation](https://img.shields.io/badge/Documentation-dartssh-blue.svg)](https://www.dartdocs.org/documentation/dartssh/latest/)

Dart SSH package providing First-class tunnelling primitives.

## Feature support

Keys: Ed25519, ECDSA, RSA.  
KEX: X25519DH, ECDH, DHGEX, DH.  
Cipher: AES-CTR, AES-CBC.  
MAC: MD5, SHA.  
Compression: not yet supported.  
Forwarding: TCP/IP, Agent.  
Tunneling drop-ins for: Socket, WebSocket, package:http.

## Example

See [example/dartssh.dart](example/dartssh.dart).

## Build

Follow the same procedure as [the continuous integration](.travis.yml).

## License

dartssh is released under the terms of the MIT license. See [LICENSE](LICENSE).

