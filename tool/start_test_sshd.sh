#!/usr/bin/env bash
# Builds and starts the OpenSSH server the interop tests run against.
#
# The image is built from tool/test-sshd so the algorithms the server offers
# are known exactly. Run this, then:
#
#   DARTSSH2_LOCAL_SSHD=1 dart test --tags=integration
set -euo pipefail

NAME="${SSHD_CONTAINER_NAME:-dartssh2-test-sshd}"
PORT="${SSHD_PORT:-2222}"
TAG="${SSHD_IMAGE_TAG:-dartssh2-test-sshd:local}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker build -t "$TAG" "$HERE/test-sshd"
docker run -d --name "$NAME" -p "127.0.0.1:${PORT}:2222" "$TAG" >/dev/null

echo "Waiting for sshd on 127.0.0.1:${PORT}..."
for _ in $(seq 1 60); do
  if (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null; then
    exec 3<&- 3>&-
    echo "sshd is up. Algorithms it offers:"
    docker exec "$NAME" /usr/sbin/sshd -T -f /etc/ssh/sshd_config \
      | grep -iE '^(kexalgorithms|ciphers|macs) '
    exit 0
  fi
  sleep 1
done

echo "sshd did not come up in time" >&2
docker logs "$NAME" >&2 || true
exit 1
