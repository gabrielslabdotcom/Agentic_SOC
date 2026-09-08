#!/usr/bin/env bash
# Forward Pop's localhost analyst UI to this Mac without colliding with a local uvicorn on 8080.
set -euo pipefail

LOCAL_PORT="${1:-8081}"

echo "Tunnel: Pop 127.0.0.1:8080  →  this Mac 127.0.0.1:${LOCAL_PORT}"
echo "Open LIVE Pop cases: http://127.0.0.1:${LOCAL_PORT}/"
echo "(Mac uvicorn on 8080, if running, stays the local copy.)"
echo "Leave this terminal open. Ctrl-C closes the tunnel."
exec ssh -N -L "${LOCAL_PORT}:127.0.0.1:8080" soc
