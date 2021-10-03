# DartSSH 2

[![pub package](https://img.shields.io/pub/v/dartssh.svg)](https://pub.dartlang.org/packages/dartssh) [![Build Status](https://travis-ci.org/GreenAppers/dartssh.svg?branch=master)](https://travis-ci.org/GreenAppers/dartssh) [![Coverage Status](https://coveralls.io/repos/github/GreenAppers/dartssh/badge.svg?branch=master)](https://coveralls.io/github/GreenAppers/dartssh?branch=master) [![documentation](https://img.shields.io/badge/Documentation-dartssh-blue.svg)](https://www.dartdocs.org/documentation/dartssh/latest/)

`dartssh2`  is a fork of `dartssh`, the pure Dart SSH implementation, with bug fixes, up-to-date dependencies and sound null safety.

`dartssh2` providing first-class tunnelling primitives.

## Feature support

| <!-- -->                   | <!-- -->                        |
|----------------------------|---------------------------------|
| **Keys**                   | Ed25519, ECDSA, RSA             |
| **KEX**                    | X25519DH, ECDH, DHGEX, DH       |
| **Cipher**                 | AES-CTR, AES-CBC                |
| **MAC**                    | MD5, SHA                        |
| **Compression**            | not yet supported               |
| **Forwarding**             | TCP/IP, Agent                   |
| **Tunneling** drop-ins for | Socket, WebSocket, package:http |

## Quick start - SSH client

<!-- <table><tbody ><tr></tr><tr><td> -->
<details >
<summary>
<sub><b>Click to see more:</b></sub>
<!-- <h6>Import required files</h6> -->

```dart
import 'package:dartssh2/client.dart';
```
</summary>
<!-- <hr> -->
<h6>Write the following HTML</h6>

 ```html
<div class="container">
    <canvas id="myChart"></canvas>
</div>
```
<h6>... and JS</h6>

```js
var data = {{ chartJSON | safe }}
var ctx = document.getElementById("myChart").getContext('2d');
var myChart = new Chart(ctx, data);
```
</details>
<!-- </td></tr></tbody></table> -->

## Quick start - SSH server

<!-- <table><tbody ><tr></tr><tr><td> -->
<details >
<summary>
<sub><b>Click to see more:</b></sub>
<!-- <h6>Import required files</h6> -->

```dart
import 'package:dartssh2/client.dart';
```
</summary>
<!-- <hr> -->
<h6>Write the following HTML</h6>

 ```html
<div class="container">
    <canvas id="myChart"></canvas>
</div>
```
<h6>... and JS</h6>

```js
var data = {{ chartJSON | safe }}
var ctx = document.getElementById("myChart").getContext('2d');
var myChart = new Chart(ctx, data);
```
</details>
<!-- </td></tr></tbody></table> -->

## Example

SSH client: [example/dartssh.dart](example/dartssh.dart)

SSH server: [example/dartsshs.dart](example/dartsshs.dart)
## Credits

https://github.com/GreenAppers/dartssh by GreenAppers

## License

dartssh is released under the terms of the MIT license. See [LICENSE](LICENSE).