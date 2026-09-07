#!/usr/bin/env python3
"""
Triage quality eval harness.

Loads labeled alerts, runs score_alert + should_open_case, prints accuracy /
confusion by category, exits non-zero if below configured thresholds.
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

from agentic_soc.triage import score_alert, should_open_case  # noqa: E402

_DEFAULT_FIXTURE = _ROOT / "evals" / "labeled_alerts.json"


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Eval triage scoring against labeled alerts")
    p.add_argument(
        "--fixtures",
        type=Path,
        default=_DEFAULT_FIXTURE,
        help=f"Labeled alerts JSON (default: {_DEFAULT_FIXTURE})",
    )
    p.add_argument(
        "--min-disposition-accuracy",
        type=float,
        default=None,
        help="Override fixture threshold for disposition accuracy",
    )
    p.add_argument(
        "--min-open-case-accuracy",
        type=float,
        default=None,
        help="Override fixture threshold for open-case accuracy",
    )
    p.add_argument("--json-out", type=Path, default=None, help="Write detailed report JSON")
    p.add_argument("-q", "--quiet", action="store_true", help="Less per-alert output")
    return p.parse_args()


def _disposition_ok(got: str, expected: list[str] | str) -> bool:
    allowed = expected if isinstance(expected, list) else [expected]
    return got in allowed


def run_eval(
    fixtures_path: Path,
    *,
    min_disposition_accuracy: float | None = None,
    min_open_case_accuracy: float | None = None,
) -> dict[str, Any]:
    data = json.loads(fixtures_path.read_text())
    items = data.get("alerts") or []
    thresholds = data.get("thresholds") or {}
    disp_floor = (
        min_disposition_accuracy
        if min_disposition_accuracy is not None
        else float(thresholds.get("min_disposition_accuracy", 0.8))
    )
    open_floor = (
        min_open_case_accuracy
        if min_open_case_accuracy is not None
        else float(thresholds.get("min_open_case_accuracy", 0.85))
    )

    sibling_alerts = [row["alert"] for row in items if isinstance(row.get("alert"), dict)]

    results: list[dict[str, Any]] = []
    by_category: dict[str, dict[str, int]] = defaultdict(lambda: {"n": 0, "disp_ok": 0, "open_ok": 0})
    confusion: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    disp_ok_total = 0
    open_ok_total = 0

    for row in items:
        alert = row["alert"]
        expected = row.get("expected") or {}
        category = str(row.get("category") or "uncategorized")
        label_id = str(row.get("id") or alert.get("id") or "?")

        judgment = score_alert(alert)
        gate = should_open_case(alert, judgment, sibling_alerts=sibling_alerts)

        exp_disp = expected.get("disposition", [])
        if isinstance(exp_disp, str):
            exp_disp = [exp_disp]
        got_disp = judgment["disposition"]
        disp_match = _disposition_ok(got_disp, exp_disp)

        exp_open = bool(expected.get("open_case"))
        got_open = bool(gate["open"])
        open_match = got_open == exp_open

        # Confusion key: expected primary → predicted
        exp_key = "|".join(exp_disp) if exp_disp else "?"
        confusion[exp_key][got_disp] += 1

        by_category[category]["n"] += 1
        if disp_match:
            by_category[category]["disp_ok"] += 1
            disp_ok_total += 1
        if open_match:
            by_category[category]["open_ok"] += 1
            open_ok_total += 1

        results.append(
            {
                "id": label_id,
                "category": category,
                "rule_id": alert.get("rule_id"),
                "description": alert.get("description"),
                "expected_disposition": exp_disp,
                "got_disposition": got_disp,
                "disposition_ok": disp_match,
                "expected_open_case": exp_open,
                "got_open_case": got_open,
                "open_case_reason": gate.get("reason"),
                "open_case_ok": open_match,
                "judgment": judgment,
            }
        )

    n = len(results) or 1
    disp_acc = disp_ok_total / n
    open_acc = open_ok_total / n
    passed = disp_acc >= disp_floor and open_acc >= open_floor

    return {
        "fixture": str(fixtures_path),
        "n": len(results),
        "disposition_accuracy": round(disp_acc, 4),
        "open_case_accuracy": round(open_acc, 4),
        "thresholds": {
            "min_disposition_accuracy": disp_floor,
            "min_open_case_accuracy": open_floor,
        },
        "passed": passed,
        "by_category": {
            cat: {
                "n": stats["n"],
                "disposition_accuracy": round(stats["disp_ok"] / stats["n"], 4) if stats["n"] else 0.0,
                "open_case_accuracy": round(stats["open_ok"] / stats["n"], 4) if stats["n"] else 0.0,
            }
            for cat, stats in sorted(by_category.items())
        },
        "confusion_expected_to_got": {k: dict(v) for k, v in sorted(confusion.items())},
        "failures": [r for r in results if not (r["disposition_ok"] and r["open_case_ok"])],
        "results": results,
    }


def _print_report(report: dict[str, Any], *, quiet: bool) -> None:
    print("=== Agentic SOC triage eval ===\n")
    print(f"Fixture: {report['fixture']}")
    print(f"Alerts:  {report['n']}")
    print(
        f"Disposition accuracy: {report['disposition_accuracy']:.1%} "
        f"(threshold {report['thresholds']['min_disposition_accuracy']:.0%})"
    )
    print(
        f"Open-case accuracy:   {report['open_case_accuracy']:.1%} "
        f"(threshold {report['thresholds']['min_open_case_accuracy']:.0%})"
    )
    print()
    print("By category:")
    for cat, stats in report["by_category"].items():
        print(
            f"  {cat:20s} n={stats['n']:2d}  "
            f"disp={stats['disposition_accuracy']:.0%}  "
            f"open={stats['open_case_accuracy']:.0%}"
        )
    print()
    print("Confusion (expected → got counts):")
    for exp, got_map in report["confusion_expected_to_got"].items():
        parts = ", ".join(f"{g}:{c}" for g, c in sorted(got_map.items()))
        print(f"  {exp} → {parts}")

    failures = report["failures"]
    if failures:
        print()
        print(f"Failures ({len(failures)}):")
        for f in failures:
            print(
                f"  [{f['id']}] cat={f['category']} "
                f"disp expected={f['expected_disposition']} got={f['got_disposition']} "
                f"open expected={f['expected_open_case']} got={f['got_open_case']} "
                f"({f['open_case_reason']})"
            )
    elif not quiet:
        print()
        print("All labeled alerts matched disposition + open-case expectations.")

    print()
    print("PASS" if report["passed"] else "FAIL")


def main() -> int:
    args = _parse_args()
    if not args.fixtures.is_file():
        print(f"Fixture not found: {args.fixtures}", file=sys.stderr)
        return 2
    report = run_eval(
        args.fixtures,
        min_disposition_accuracy=args.min_disposition_accuracy,
        min_open_case_accuracy=args.min_open_case_accuracy,
    )
    _print_report(report, quiet=args.quiet)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        # Drop bulky per-alert judgment reasons for a leaner file? keep full for debugging
        args.json_out.write_text(json.dumps(report, indent=2, default=str))
        print(f"Wrote report: {args.json_out}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
