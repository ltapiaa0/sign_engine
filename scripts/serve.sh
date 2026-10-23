#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ADDR="${1:-127.0.0.1:8080}"
[ -x "$ROOT/build/server" ] || "$ROOT/scripts/build.sh" server.bend
mkdir -p jobs
exec systemd-socket-activate --inetd --accept --listen="$ADDR" "$ROOT/build/server"
