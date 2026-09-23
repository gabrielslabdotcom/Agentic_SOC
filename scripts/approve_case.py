#!/usr/bin/env python3
"""
Human-approval stub for propose_action cases.

Records an analyst closing outcome (status + notes). Never executes containment.
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

from agentic_soc.analyst_outcomes import (  # noqa: E402
    ANALYST_DISPOSITIONS,
    coerce_analyst_disposition,
    skips_repeats,
)
from agentic_soc.policy import ANALYST  # noqa: E402
from agentic_soc.tools import SocTools  # noqa: E402


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Record an analyst closing outcome (lab-safe; no containment)"
    )
    p.add_argument("--case-id", type=int, required=True, help="Case ID from data/cases.sqlite")
    p.add_argument(
        "--disposition",
        choices=sorted(ANALYST_DISPOSITIONS),
        help="Closing outcome (preferred)",
    )
    g = p.add_mutually_exclusive_group()
    g.add_argument(
        "--approve",
        action="store_true",
        help="Deprecated alias for --disposition confirmed_compromise",
    )
    g.add_argument(
        "--reject",
        action="store_true",
        help="Deprecated alias for --disposition false_positive",
    )
    p.add_argument("--note", default="", help="Optional human note")
    p.add_argument("--author", default="human", help="Note author (default: human)")
    p.add_argument("--json", action="store_true", help="Print updated case as JSON")
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    if not args.disposition and not args.approve and not args.reject:
        print("Provide --disposition or --approve/--reject", file=sys.stderr)
        return 2
    try:
        outcome = coerce_analyst_disposition(
            disposition=args.disposition,
            approved=True if args.approve else False if args.reject else None,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    tools = SocTools(role=ANALYST)
    before = tools.get_case(args.case_id)
    if before.get("error"):
        print(f"Case not found: {args.case_id}", file=sys.stderr)
        return 1

    updated = tools.resolve_proposal(
        args.case_id,
        disposition=outcome,
        note=args.note,
        author=args.author,
    )
    if updated.get("error"):
        print(updated.get("error"), file=sys.stderr)
        return 1

    print(f"=== Analyst outcome: {outcome} case #{args.case_id} ===\n")
    print(f"Title:    {updated.get('title')}")
    print(f"Status:   {before.get('status')} → {updated.get('status')}")
    print(f"Proposed: {updated.get('recommended_action')}")
    print(f"Machine disposition: {updated.get('disposition')}")
    print(f"Analyst disposition: {updated.get('analyst_disposition')}")
    print(f"Skip repeats: {'yes' if skips_repeats(outcome) else 'no'}")
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
