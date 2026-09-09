#!/usr/bin/env python3
"""Print Pop autonomy + dashboard status via SSH host `soc`."""

from __future__ import annotations

import subprocess
import sys

_REMOTE = r"""
set -e
echo "=== units ==="
echo -n "autonomy:  "; systemctl --user is-active agentic-soc-autonomy.service || true
echo -n "dashboard: "; systemctl --user is-active agentic-soc-dashboard.service || true
echo
echo "=== autonomy status (head) ==="
systemctl --user status agentic-soc-autonomy.service --no-pager -l 2>/dev/null | head -18 || true
echo
echo "=== dashboard status (head) ==="
systemctl --user status agentic-soc-dashboard.service --no-pager -l 2>/dev/null | head -12 || true
echo
echo "=== autonomy_state last_cycle ==="
python3 - <<'PY'
import json
from pathlib import Path
p = Path("/home/admin/Agentic_SOC/data/autonomy_state.json")
if not p.exists():
    print("{}")
else:
    data = json.loads(p.read_text())
    out = {
        "cycles": data.get("cycles"),
        "cases_opened_total": data.get("cases_opened_total"),
        "updated_at": data.get("updated_at"),
        "last_seen_timestamp": data.get("last_seen_timestamp"),
        "seen_alert_ids_count": len(data.get("seen_alert_ids") or []),
        "last_cycle": data.get("last_cycle") or {},
    }
    print(json.dumps(out, indent=2))
PY
"""


def _ssh() -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=8",
            "soc",
            _REMOTE,
        ],
        capture_output=True,
        text=True,
        timeout=25,
        check=False,
    )


def main() -> int:
    print("Querying Pop via `ssh soc` …")
    try:
        proc = _ssh()
    except FileNotFoundError:
        print("ssh not found on this Mac.", file=sys.stderr)
        return 1
    except subprocess.TimeoutExpired:
        print("ssh soc timed out.", file=sys.stderr)
        _hint()
        return 1

    if proc.returncode != 0 and not proc.stdout.strip():
        err = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
        print(f"ssh soc failed: {err}", file=sys.stderr)
        _hint()
        return proc.returncode or 1

    sys.stdout.write(proc.stdout)
    if proc.stderr.strip():
        print("--- stderr ---", file=sys.stderr)
        sys.stderr.write(proc.stderr)
    print()
    _hint()
    return 0 if proc.returncode == 0 else proc.returncode


def _hint() -> None:
    print("Open live analyst UI: http://192.168.50.254:8080/")
    print("Mac uvicorn on :8080 is the local fixture DB, not Discord cases.")
    print("Optional fallback: ./scripts/tunnel_pop_dashboard.sh → http://127.0.0.1:8081/")


if __name__ == "__main__":
    raise SystemExit(main())
