#!/usr/bin/env python3
"""
Human-approval stub for propose_action cases.

Records approve/reject on a case (status + notes). Never executes containment.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from agentic_soc.tools import SocTools  # noqa: E402


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Approve or reject a proposed case action (lab-safe; no containment)"
    )
    p.add_argument("--case-id", type=int, required=True, help="Case ID from data/cases.sqlite")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--approve", action="store_true", help="Approve the proposed action")
    g.add_argument("--reject", action="store_true", help="Reject the proposed action")
    p.add_argument("--note", default="", help="Optional human note")
    p.add_argument("--author", default="human", help="Note author (default: human)")
    p.add_argument("--json", action="store_true", help="Print updated case as JSON")
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    tools = SocTools()
    before = tools.get_case(args.case_id)
    if before.get("error"):
        print(f"Case not found: {args.case_id}", file=sys.stderr)
        return 1

    updated = tools.resolve_proposal(
        args.case_id,
        approved=bool(args.approve),
        note=args.note,
        author=args.author,
    )

    decision = "APPROVED" if args.approve else "REJECTED"
    print(f"=== Human approval: {decision} case #{args.case_id} ===\n")
    print(f"Title:    {updated.get('title')}")
    print(f"Status:   {before.get('status')} → {updated.get('status')}")
    print(f"Proposed: {updated.get('recommended_action')}")
    print(f"Disposition: {updated.get('disposition')}")
    print("Containment: not executed (lab stub)")
    if args.note:
        print(f"Note: {args.note}")
    print(f"\nCases DB: {tools.settings.cases_path}")

    if args.json:
        print()
        print(json.dumps(updated, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
