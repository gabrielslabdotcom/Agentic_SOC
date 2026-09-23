#!/usr/bin/env python3
"""
Summarize human Approve / Reject feedback from cases.sqlite.

Used to inspect skip keys (rule_id + source_ip) after Phase C rejects.
Does not execute containment.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from agentic_soc.cases import CaseStore  # noqa: E402
from agentic_soc.config import get_settings  # noqa: E402


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Summarize triage Approve / Reject feedback")
    p.add_argument(
        "--db",
        type=Path,
        default=None,
        help="cases.sqlite path (default: CASES_DB_PATH / settings)",
    )
    p.add_argument("--limit", type=int, default=50, help="Recent feedback rows to list")
    p.add_argument("--json", action="store_true", help="Print JSON instead of text")
    return p.parse_args()


def summarize(store: CaseStore, *, limit: int = 50) -> dict[str, Any]:
    summary = store.feedback_summary(limit=limit)
    skip_keys: dict[tuple[str, str], int] = defaultdict(int)
    for row in summary.get("items") or []:
        if row.get("approved"):
            ad = str(row.get("analyst_disposition") or "")
            if ad == "confirmed_compromise" or not ad:
                continue
        rid = str(row.get("rule_id") or "").strip()
        sip = str(row.get("source_ip") or "").strip()
        if rid and sip:
            skip_keys[(rid, sip)] += 1
    skip_list = [
        {"rule_id": rid, "source_ip": sip, "reject_count": n}
        for (rid, sip), n in sorted(skip_keys.items(), key=lambda x: (-x[1], x[0]))
    ]
    metrics = store.queue_metrics()
    suggestions = store.suppression_suggestions(min_count=2, limit=15)
    return {
        **summary,
        "skip_keys": skip_list,
        "skip_key_count": len(skip_list),
        "queue_metrics": metrics,
        "suppression_suggestions": suggestions.get("suggestions") or [],
    }


def main() -> int:
    args = _parse_args()
    db = args.db
    if db is None:
        db = Path(get_settings().cases_path)
    store = CaseStore(db)
    report = summarize(store, limit=args.limit)
    if args.json:
        print(json.dumps(report, indent=2, default=str))
        return 0

    print(f"db={db}")
    qm = report.get("queue_metrics") or {}
    print(
        f"queue open={qm.get('open', 0)} auto_closed={qm.get('auto_closed', 0)} "
        f"human_closed={qm.get('human_closed', 0)} "
        f"suppressions={qm.get('active_suppressions', 0)} "
        f"cases_total={qm.get('cases_total', 0)}"
    )
    print(
        f"feedback n={report.get('count', 0)} "
        f"approved={report.get('approved', 0)} "
        f"rejected={report.get('rejected', 0)}"
    )
    print(f"skip keys (rejected rule_id+source_ip): {report['skip_key_count']}")
    for item in report["skip_keys"]:
        print(
            f"  skip rule={item['rule_id']} src={item['source_ip']} "
            f"rejects={item['reject_count']}"
        )
    suggestions = report.get("suppression_suggestions") or []
    if suggestions:
        print(f"suppression suggestions (review before adding): {len(suggestions)}")
        for item in suggestions:
            src = item.get("source_ip") or "any"
            print(
                f"  suggest rule={item['rule_id']} src={src} "
                f"count={item['count']} → {item.get('suggested_disposition')}"
            )
    print("recent:")
    for row in report.get("items") or []:
        decision = str(row.get("analyst_disposition") or ("APPROVE" if row.get("approved") else "REJECT"))
        print(
            f"  [{decision}] case={row.get('case_id')} rule={row.get('rule_id')} "
            f"src={row.get('source_ip')} disp={row.get('disposition')} "
            f"note={row.get('note')}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
