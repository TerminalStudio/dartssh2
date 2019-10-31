# dartssh [![Build Status](https://travis-ci.org/GreenAppers/dartssh.svg?branch=master)](https://travis-ci.org/GreenAppers/dartssh)

Library providing a pure Dart SSH implementation.

## Feature support

Keys: Ed25519, ECDSA, RSA.  
KEX: X25519DH, ECDH, DHGEX, DH.  
Cipher: AES-CTR, AES-CBC.  
MAC: MD5, SHA.  
Compression: not yet supported.  
Forwarding: TCP/IP, Agent.  

## Example

See [example/ssh.dart](example/ssh.dart).

## Build

Follow the same procedure as [the continuous integration](.travis.yml).

## License

dartssh is released under the terms of the MIT license. See [LICENSE](LICENSE).

