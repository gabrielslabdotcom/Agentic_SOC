#!/usr/bin/env bash
# Optional fallback if the LAN UI is unreachable. Live analyst UI is
# http://192.168.50.254:8080/ (UFW allowlisted). Mac uvicorn on 8080 is
# this repo's cases.sqlite only — not Discord / autonomy cases.
set -euo pipefail

LOCAL_PORT="${1:-8081}"

echo "Optional tunnel: Pop 127.0.0.1:8080  →  this Mac 127.0.0.1:${LOCAL_PORT}"
echo "Preferred live UI: http://192.168.50.254:8080/"
echo "Tunnel fallback: http://127.0.0.1:${LOCAL_PORT}/"
echo "(Mac uvicorn on 8080, if running, stays the local copy.)"
echo "Leave this terminal open. Ctrl-C closes the tunnel."
exec ssh -N -L "${LOCAL_PORT}:127.0.0.1:8080" soc
