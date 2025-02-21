<!-- Title-->
<h1 align="center">DartSSH 2</h1>

<!-- Badges-->
<p align="center">
  <a href="https://pub.dartlang.org/packages/dartssh2">
    <img src="https://img.shields.io/pub/v/dartssh2.svg" alt="DartSSH2 package version on Pub">
  </a>
  <a href="https://www.dartdocs.org/documentation/dartssh2/latest/">
    <img src="https://img.shields.io/badge/Docs-dartssh2-blue.svg" alt="DartSSH2 documentation">
  </a>
  <a href="https://github.com/TerminalStudio/dartssh2/actions/workflows/dart.yml">
    <img src="https://github.com/TerminalStudio/dartssh2/actions/workflows/dart.yml/badge.svg" alt="DartSSH2 GitHub Actions workflow status">
  </a>
  <a href="https://ko-fi.com/F1F61K6BL">
    <img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-F16061?style=flat&logo=buy-me-a-coffee&logoColor=white&labelColor=555555" alt="Support me on Ko-fi">
  </a>
</p>

<p style="text-align: center;">
SSH and SFTP client written in pure Dart, aiming to be feature-rich as well as easy to use.
</p>

> **dartssh2** is now a complete rewrite of [dartssh].

## ✨ Features

-  **Pure Dart**: Working with both Dart VM and Flutter.
-  **SSH Session**: Executing commands, spawning shells, setting environment variables, pseudo terminals, etc.
-  **Authentication**: Supports password, private key and interactive authentication method.
-  **Forwarding**: Supports local forwarding and remote forwarding.
-  **SFTP**: Supports all operations defined in [SFTPv3 protocol](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02) including upload, download, list, link, remove, rename, etc.

## 🧬 Built with dartssh2

<table>
  <tr>
    <!-- ServerBox -->
    <td style="text-align: center;">
      <b><a href="https://github.com/LollipopKit/flutter_server_box">ServerBox</a></b>
    </td>
    <!-- NoPorts -->
    <td style="text-align: center;">
      <b><a href="https://github.com/atsign-foundation/noports">NoPorts</a></b>
    </td>
    <!-- dartShell -->
    <td style="text-align: center;">
      <b><a href="https://github.com/hsduren/dartshell">DartShell</a></b>
    </td>
  </tr>

  <tr> 
    <!-- ServerBox -->
    <td>
      <img src="https://raw.githubusercontent.com/TerminalStudio/dartssh2/master/media/showcase-1-serverbox.1.jpg" width="150px" alt="ServerBox interface displaying connection management options">
      <img src="https://raw.githubusercontent.com/TerminalStudio/dartssh2/master/media/showcase-1-serverbox.2.png" width="150px" alt="ServerBox user interface for server control and monitoring">
    </td>
    <!-- NoPorts -->
    <td>
      <a href="https://asciinema.org/a/496148">
        <img src="https://user-images.githubusercontent.com/6131216/185263634-07e8dba7-b5a8-44fc-ac44-8703e247143f.png" width="300px" alt="NoPorts demo showcasing SSH connectivity without open ports">
      </a>
    </td>
    <!-- dartShell -->
    <td>
      <img src="https://github.com/hsduren/dartshell/blob/main/info1.png" width="300px" alt="dartShell displaying terminal and session information for SSH operations">
    </td>
  </tr>
</table>


> Feel free to add your own app here by opening a pull request.



## 🧪 Try

```sh
# Install the `dartssh` command.
dart pub global activate dartssh2_cli

# Then use `dartssh` as regular `ssh` command.
dartssh user@example.com

# Example: execute a command on remote host.
dartssh user@example.com ls -al

# Example: connect to a non-standard port.
dartssh user@example.com:<port>

# Transfer files via SFTP.
dartsftp user@example.com
```

> If the `dartssh` command can't be found after installation, you might need to [set up your path](https://dart.dev/tools/pub/cmd/pub-global#running-a-script-from-your-path).

## 🚀 Quick start 

### Connect to a remote host
```dart
void main() async {
  final client = SSHClient(
    await SSHSocket.connect('localhost', 22),
    username: '<username>',
    onPasswordRequest: () => '<password>',
  );
}
```

> `SSHSocket` is an interface and it's possible to implement your own `SSHSocket` if you want to use a different underlying transport rather than standard TCP socket. For example WebSocket or Unix domain socket.

### Spawn a shell on remote host

```dart
void main() async {
  final shell = await client.shell();
  stdout.addStream(shell.stdout); // listening for stdout
  stderr.addStream(shell.stderr); // listening for stderr
  stdin.cast<Uint8List>().listen(shell.write); // writing to stdin

  await shell.done; // wait for shell to exit
  client.close();
}
```

### Execute a command on remote host


```dart
void main() async {
  final uptime = await client.run('uptime');
  print(utf8.decode(uptime));
}
```

Ignoring stderr:
```dart
void main() async {
  final uptime = await client.run('uptime', stderr: false);
  print(utf8.decode(uptime));
}
```

> `client.run()` is a convenience method that wraps `client.execute()` for running non-interactive commands.

### Start a process on remote host
```dart
void main() async {
  final session = await client.execute('cat > file.txt');
  await session.stdin.addStream(File('local_file.txt').openRead().cast());
  await session.stdin.close(); // Close the sink to send EOF to the remote process.

  await session.done; // Wait for session to exit to ensure all data is flushed to the remote process.
  print(session.exitCode); // You can get the exit code after the session is done
}
```

> `session.write()` is a shorthand for `session.stdin.add()`. It's recommended to use `session.stdin.addStream()` instead of `session.write()` when you want to stream large amount of data to the remote process.

**Killing a remote process by sending signal**

```dart
void main() async {
  session.kill(SSHSignal.KILL);
  await session.done;
  print('exitCode: ${session.exitCode}'); // -> exitCode: null
  print('signal: ${session.exitSignal?.signalName}'); // -> signal: KILL
}
```

Processes killed by signals do not have an exit code, instead they have an exit signal property.

### Forward connections on local port 8080 to the server

```dart
void main() async {
  final serverSocket = await ServerSocket.bind('localhost', 8080);
  await for (final socket in serverSocket) {
    final forward = await client.forwardLocal('httpbin.org', 80);
    forward.stream.cast<List<int>>().pipe(socket);
    socket.pipe(forward.sink);
  }
}
```

### Forward connections to port 2222 on the server to local port 22

```dart
void main() async {
  final forward = await client.forwardRemote(port: 2222);

  if (forward == null) {
    print('Failed to forward remote port');
    return;
  }

  await for (final connection in forward.connections) {
    final socket = await Socket.connect('localhost', 22);
    connection.stream.cast<List<int>>().pipe(socket);
    socket.pipe(connection.sink);
  }
}
```

### Authenticate with public keys

```dart
void main() async {
  final client = SSHClient(
    socket,
    username: '<username>',
    identities: [
      // A single private key file may contain multiple keys.
      ...SSHKeyPair.fromPem(await File('path/to/id_rsa').readAsString())
    ],
  );
}
```

### Use encrypted PEM files
```dart
void main() async {
  // Test whether the private key is encrypted.
  final encrypted = SSHKeyPair.isEncrypted(await File('path/to/id_rsa').readAsString());
  print(encrypted);

// If the private key is encrypted, you need to provide the passphrase.
  final keys = SSHKeyPair.fromPem('<pem text>', '<passphrase>');
  print(keys);
}
```

Decrypt PEM file with [`compute`](https://api.flutter.dev/flutter/foundation/compute-constant.html) in Flutter

```dart
void main() async {
  List<SSHKeyPair> decryptKeyPairs(List<String> args) {
    return SSHKeyPair.fromPem(args[0], args[1]);
  }

  final keypairs = await compute(decryptKeyPairs, ['<pem text>', '<passphrase>']);
}
```

### Get the version of SSH server

```dart
void main() async {
  await client.authenticated;
  print(client.remoteVersion); // SSH-2.0-OpenSSH_7.4p1
}
```

### Connect through a jump server

```dart
void main() async {
  final jumpServer = SSHClient(
    await SSHSocket.connect('<jump server>', 22),
    username: '...',
    onPasswordRequest: () => '...',
  );

  final client = SSHClient(
    await jumpServer.forwardLocal('<target server>', 22),
    username: '...',
    onPasswordRequest: () => '...',
  );

  print(utf8.decode(await client.run('hostname'))); // -> hostname of  <target server>
}
```
}


## SFTP

### List remote directory
```dart
void main() async {
  final sftp = await client.sftp();
  final items = await sftp.listdir('/');
  for (final item in items) {
    print(item.longname);
  }
}
```

### Read remote file
```dart
void main() async {
  final sftp = await client.sftp();
  final file = await sftp.open('/etc/passwd');
  final content = await file.readBytes();
  print(latin1.decode(content));
}
```

### Write remote file
```dart
void main() async {
  final sftp = await client.sftp();
  final file = await sftp.open('file.txt', mode: SftpFileOpenMode.write);
  await file.writeBytes(utf8.encode('hello there!') as Uint8List);
}
```

**Write at specific offset**
```dart
void main() async {
  final data = utf8.encode('world') as Uint8List;
  await file.writeBytes(data, offset: 6);
}
```

### File upload
```dart
void main() async {
  final sftp = await client.sftp();
  final file = await sftp.open('file.txt', mode: SftpFileOpenMode.create | SftpFileOpenMode.write);
  await file.write(File('local_file.txt').openRead().cast());
}
```

#### Pause and resume file upload
```dart
void main() async {
  final uploader = await file.write(File('local_file.txt').openRead().cast());
// ...
  await uploader.pause();
// ...
  await uploader.resume();
  await uploader.done;
}
```

**Clear the remote file before opening it**

```dart
void main() async {
  final file = await sftp.open('file.txt',
      mode: SftpFileOpenMode.create | SftpFileOpenMode.truncate | SftpFileOpenMode.write
  );
}
```

### Directory operations
```dart
void main() async {
  final sftp = await client.sftp();
  await sftp.mkdir('/path/to/dir');
  await sftp.rmdir('/path/to/dir');
}
```

### Get/Set attributes from/to remote file/directory
```dart
void main() async {
  await sftp.stat('/path/to/file');
  await sftp.setStat(
    '/path/to/file',
    SftpFileAttrs(mode: SftpFileMode(userRead: true)),
  );
}
```

### Get the type of a remote file
```dart
void main() async {
  final stat = await sftp.stat('/path/to/file');
  print(stat.type);
  // or
  print(stat.isDirectory);
  print(stat.isSocket);
  print(stat.isSymbolicLink);
  // ...
}
```

### Create a link
```dart
void main() async {
  final sftp = await client.sftp();
  sftp.link('/from', '/to');
}
```

### Get (estimated) total and free space on the remote filesystem
```dart
void main() async {
  final sftp = await client.sftp();
  final statvfs = await sftp.statvfs('/root');
  print('total: ${statvfs.blockSize * statvfs.totalBlocks}');
  print('free: ${statvfs.blockSize * statvfs.freeBlocks}');
}
```

## 🪜 Example

### SSH client:

- [example/example.dart](https://github.com/TerminalStudio/dartssh2/blob/master/example/example.dart)
- [example/execute.dart](https://github.com/TerminalStudio/dartssh2/blob/master/example/execute.dart)
- [example/forward_local.dart](https://github.com/TerminalStudio/dartssh2/blob/master/example/forward_local.dart)
- [example/forward_remote.dart](https://github.com/TerminalStudio/dartssh2/blob/master/example/forward_remote.dart)
- [example/pubkey.dart](https://github.com/TerminalStudio/dartssh2/blob/master/example/pubkey.dart)
- [example/shell.dart](https://github.com/TerminalStudio/dartssh2/blob/master/example/shell.dart)
- [example/ssh_jump.dart](https://github.com/TerminalStudio/dartssh2/blob/master/example/ssh_jump.dart)

### SFTP:
- [example/sftp_read.dart](https://github.com/TerminalStudio/dartssh2/blob/master/example/sftp_read.dart)
- [example/sftp_list.dart](https://github.com/TerminalStudio/dartssh2/blob/master/example/sftp_list.dart)
- [example/sftp_stat.dart](https://github.com/TerminalStudio/dartssh2/blob/master/example/sftp_stat.dart)
- [example/sftp_upload.dart](https://github.com/TerminalStudio/dartssh2/blob/master/example/sftp_upload.dart)
- [example/sftp_filetype.dart](https://github.com/TerminalStudio/dartssh2/blob/master/example/sftp_filetype.dart)



## 🔐 Supported algorithms

**Host key**: 
- `ssh-rsa`
- `rsa-sha2-[256|512]`
- `ecdsa-sha2-nistp[256|384|521]`
- `ssh-ed25519`

**Key exchange**: 
- `curve25519-sha256`
- `ecdh-sha2-nistp[256|384|521] `
- `diffie-hellman-group-exchange-sha[1|256]`
- `diffie-hellman-group14-sha[1|256]`
- `diffie-hellman-group1-sha1 `
  
**Cipher**: 
- `aes[128|192|256]-ctr`
- `aes[128|192|256]-cbc`

**Integrity**: 
- `hmac-md5`
- `hmac-sha1`
- `hmac-sha2-[256|512]`

**Private key**:

| **Type**            | **Decode** | **Decrypt** | **Encode** | **Encrypt** |
|---------------------|------------|-------------|------------|-------------|
| **RSA**             | ✔️         | ✔️          | ✔️         | WIP         |
| **OpenSSH RSA**     | ✔️         | ✔️          | ✔️         | WIP         |
| **OpenSSH ECDSA**   | ✔️         | ✔️          | ✔️         | WIP         |
| **OpenSSH Ed25519** | ✔️         | ✔️          | ✔️         | WIP         |


  
## ⏳ Roadmap

- [x] Fix broken tests.
- [x] Sound null safety.
- [x] Redesign API to allow starting multiple sessions.
- [x] Full SFTP.
- [ ] Server.

## References

- [`RFC 4250`](https://datatracker.ietf.org/doc/html/rfc4250) The Secure Shell (SSH) Protocol Assigned Numbers.
- [`RFC 4251`](https://datatracker.ietf.org/doc/html/rfc4251) The Secure Shell (SSH) Protocol Architecture.
- [`RFC 4252`](https://datatracker.ietf.org/doc/html/rfc4252) The Secure Shell (SSH) Authentication Protocol.
- [`RFC 4253`](https://datatracker.ietf.org/doc/html/rfc4253) The Secure Shell (SSH) Transport Layer Protocol.
- [`RFC 4254`](https://datatracker.ietf.org/doc/html/rfc4254) The Secure Shell (SSH) Connection Protocol.
- [`RFC 4255`](https://datatracker.ietf.org/doc/html/rfc4255) Using DNS to Securely Publish Secure Shell (SSH) Key Fingerprints.
- [`RFC 4256`](https://datatracker.ietf.org/doc/html/rfc4256) Generic Message Exchange Authentication for the Secure Shell Protocol (SSH).
- [`RFC 4419`](https://datatracker.ietf.org/doc/html/rfc4419) Diffie-Hellman Group Exchange for the Secure Shell (SSH) Transport Layer Protocol.
- [`RFC 4716`](https://datatracker.ietf.org/doc/html/rfc4716) The Secure Shell (SSH) Public Key File Format.
- [`RFC 5656`](https://datatracker.ietf.org/doc/html/rfc5656) Elliptic Curve Algorithm Integration in the Secure Shell Transport Layer.
- [`RFC 8332`](https://datatracker.ietf.org/doc/html/rfc8332) Use of RSA Keys with SHA-256 and SHA-512 in the Secure Shell (SSH) Protocol.
- [`RFC 8731`](https://datatracker.ietf.org/doc/html/rfc8731) Secure Shell (SSH) Key Exchange Method Using Curve25519 and Curve448.
- [`draft-miller-ssh-agent-03`](https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-03) SSH Agent Protocol.
- [`draft-ietf-secsh-filexfer-02`](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02) SSH File Transfer Protocol.
- [`draft-dbider-sha2-mac-for-ssh-06`](https://datatracker.ietf.org/doc/html/draft-dbider-sha2-mac-for-ssh-06) SHA-2 Data Integrity Verification for the Secure Shell (SSH) Transport Layer Protocol.

## Credits

- [https://github.com/GreenAppers/dartssh](https://github.com/GreenAppers/dartssh) by GreenAppers.

## License

dartssh is released under the terms of the MIT license. See [LICENSE](LICENSE).

[dartssh]: https://github.com/GreenAppers/dartssh
