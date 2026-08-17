# Security Policy

dartssh2 is an SSH and SFTP client. A defect in it can expose credentials,
session contents, or transferred files, so security reports get priority over
everything else in the issue tracker.

## Supported versions

Security fixes are released for the latest published version on
[pub.dev](https://pub.dev/packages/dartssh2). Older majors are not patched, so
upgrading is part of the fix.

## Reporting a vulnerability

**Do not open a public issue for a vulnerability.**

Report it through
[GitHub private vulnerability reporting](https://github.com/vicajilau/dartssh2/security/advisories/new),
which keeps the discussion private until a fix is published.

A useful report includes:

- The version of dartssh2 and of the Dart SDK.
- What an attacker gains, and what position they need to be in (network
  attacker, malicious server, local user).
- A reproduction: a short Dart program, the server involved, or a packet
  capture.

You can expect an acknowledgement within a week. Once a fix is ready it is
published to pub.dev together with an advisory crediting you, unless you
prefer otherwise.

## What is in scope

Anything that lets an attacker read or alter a session they should not be able
to: flaws in key exchange, host key verification, authentication, packet
parsing, or the SFTP layer.

Two behaviours are documented rather than defects:

- **Host key identity is not checked unless you check it.** The signature on
  the host key is always verified, but deciding whether that key is the one you
  expected is the caller's job, through `onVerifyHostKey`. A client that omits
  the handler accepts any host key. See
  [Verify the host key](README.md#verify-the-host-key).
- **Weak algorithms are still implemented.** `diffie-hellman-group1-sha1`,
  `hmac-md5`, the truncated `hmac-sha2-*-96` variants, and CBC ciphers exist so
  that old servers remain reachable. The broken ones are not in the default
  preference lists and are only used when passed to `SSHAlgorithms`
  explicitly.

Reports that only point out that these options exist are not treated as
vulnerabilities. A report showing that a default configuration selects one of
them unexpectedly is.
