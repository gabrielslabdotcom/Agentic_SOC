#!/usr/bin/env bash
# Bootstrap the Agentic SOC Python app (venv + editable install + .env template).
# Does not install Wazuh, systemd units, Docker, or secrets.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

EXTRAS="dev"
PYTHON="${PYTHON:-python3}"

usage() {
  cat <<'EOF'
Usage: ./scripts/bootstrap_app.sh [--extras LIST] [--python BIN]

  --extras LIST   Comma-separated extras to install with the package.
                  Default: dev
                  Examples: dev | cursor,discord | dev,cursor,discord
  --python BIN    Python interpreter (default: python3 or $PYTHON)
  -h, --help      Show this help

Creates .venv if missing, installs the package editable, and copies
.env.example → .env only when .env does not already exist.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --extras)
      EXTRAS="${2:-}"
      shift 2
      ;;
    --python)
      PYTHON="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "error: Python not found ($PYTHON). Install Python 3.11+ or pass --python." >&2
  exit 1
fi

PY_VER="$("$PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
"$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' || {
  echo "error: need Python 3.11+, found $PY_VER ($PYTHON)" >&2
  exit 1
}

if [[ ! -d .venv ]]; then
  echo "==> Creating .venv with $PYTHON ($PY_VER)"
  "$PYTHON" -m venv .venv
else
  echo "==> Reusing existing .venv"
fi

# shellcheck disable=SC1091
source .venv/bin/activate

echo "==> Upgrading pip"
python -m pip install --upgrade pip

if [[ -n "$EXTRAS" ]]; then
  SPEC=".[${EXTRAS}]"
else
  SPEC="."
fi
echo "==> pip install -e '${SPEC}'"
python -m pip install -e "${SPEC}"

if [[ ! -f .env ]]; then
  if [[ -f .env.example ]]; then
    cp .env.example .env
    echo "==> Created .env from .env.example (edit credentials before connecting)"
  else
    echo "warning: .env.example missing; skipped .env creation" >&2
  fi
else
  echo "==> Keeping existing .env"
fi

cat <<'EOF'

Done. Next steps:
  1. Edit .env — set WAZUH_* URLs and passwords for your SIEM (do not rely on code defaults)
  2. source .venv/bin/activate
  3. python scripts/check_wazuh.py
  4. uvicorn agentic_soc.api:app --host 127.0.0.1 --port 8080

Optional: Linux systemd units under deploy/ (edit $AGENTIC_SOC_HOME paths first).
See README Quick start for MCP, Discord, and Cursor extras.
EOF
