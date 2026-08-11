#!/usr/bin/env sh
set -eu
if command -v python3 >/dev/null 2>&1; then
  exec python3 server.py --open
fi
exec python server.py --open
