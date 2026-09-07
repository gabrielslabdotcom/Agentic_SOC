#!/usr/bin/env python3
"""One-shot retry of Cursor cloud investigation for a recent case (lab)."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from agentic_soc.cursor_agent import kick_cursor_investigation  # noqa: E402
from agentic_soc.tools import SocTools  # noqa: E402


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    tools = SocTools()
    cases = tools.list_cases(limit=20).get("cases") or []
    pick = None
    for c in cases:
        blob = f"{c.get('title') or ''} {c.get('summary') or ''}".lower()
        if "port scan" in blob:
            pick = c
            break
    if pick is None and cases:
        pick = cases[0]
    if not pick:
        print("no cases to retry")
        return 1
    print(f"retrying case_id={pick.get('id')} title={(pick.get('title') or '')[:90]}")
    out = kick_cursor_investigation(pick, wait=True)
    print(
        "ok=",
        out.get("ok"),
        "status=",
        out.get("status"),
        "run_id=",
        out.get("run_id"),
        "agent_id=",
        out.get("agent_id"),
        "error=",
        (out.get("error") or "")[:300],
    )
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
