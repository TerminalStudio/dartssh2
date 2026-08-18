#!/usr/bin/env bash
# Starts the OpenSSH server the interop tests run against.
#
# The tests connect a real dartssh2 client to a real sshd, so a mistake in what
# we put on the wire fails here rather than in someone's application. Run this,
# then `DARTSSH2_LOCAL_SSHD=1 dart test --tags=integration`.
set -euo pipefail

NAME="${SSHD_CONTAINER_NAME:-dartssh2-test-sshd}"
PORT="${SSHD_PORT:-2222}"
IMAGE="${SSHD_IMAGE:-lscr.io/linuxserver/openssh-server:latest}"

docker rm -f "$NAME" >/dev/null 2>&1 || true

docker run -d --name "$NAME" \
  -e PUID=1000 \
  -e PGID=1000 \
  -e PASSWORD_ACCESS=true \
  -e USER_NAME=dartssh2 \
  -e USER_PASSWORD=dartssh2-test-password \
  -e SUDO_ACCESS=false \
  -p "127.0.0.1:${PORT}:2222" \
  "$IMAGE" >/dev/null

echo "Waiting for sshd on 127.0.0.1:${PORT}..."
for _ in $(seq 1 60); do
  if (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null; then
    exec 3<&- 3>&-
    echo "sshd is up"
    exit 0
  fi
  sleep 1
done

echo "sshd did not come up in time" >&2
docker logs "$NAME" >&2 || true
exit 1
