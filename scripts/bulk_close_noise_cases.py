#!/usr/bin/env python3
"""
One-shot close of leftover open noise cases (e.g. historical rule 2501 flood).

Default is dry-run. Never executes containment.
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

from agentic_soc.analyst_outcomes import ANALYST_DISPOSITIONS  # noqa: E402
from agentic_soc.cases import CaseStore  # noqa: E402
from agentic_soc.config import get_settings  # noqa: E402


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Bulk-close open cases by rule_id")
    p.add_argument("--rule-id", default="2501", help="Wazuh rule id to close (default: 2501)")
    p.add_argument(
        "--disposition",
        default="false_positive",
        choices=sorted(ANALYST_DISPOSITIONS),
    )
    p.add_argument("--note", default="bulk close leftover self-ingest / noise")
    p.add_argument("--limit", type=int, default=2000)
    p.add_argument("--apply", action="store_true", help="Write closes (otherwise dry-run)")
    p.add_argument("--db", type=Path, default=None)
    p.add_argument("--json", action="store_true")
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    db = args.db or Path(get_settings().cases_path)
    store = CaseStore(db)
    listed = store.list_cases(status="open", limit=max(1, args.limit))
    matches = [
        c
        for c in listed.get("cases") or []
        if str(c.get("rule_id") or "") == str(args.rule_id)
    ]
    report = {
        "db": str(db),
        "rule_id": args.rule_id,
        "disposition": args.disposition,
        "open_scanned": listed.get("count"),
        "matched": len(matches),
        "applied": False,
        "ids": [c.get("id") for c in matches],
    }
    if args.apply and matches:
        result = store.resolve_proposals(
            [int(c["id"]) for c in matches],
            disposition=args.disposition,
            note=args.note,
            author="bulk_close_noise",
        )
        report["applied"] = True
        report["result"] = result
    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print(
            f"db={db} rule={args.rule_id} matched={len(matches)} "
            f"apply={args.apply} disposition={args.disposition}"
        )
        print("ids:", ", ".join(str(i) for i in report["ids"][:40]) or "(none)")
        if not args.apply:
            print("dry-run; pass --apply to close")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
