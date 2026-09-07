#!/usr/bin/env python3
"""
Closed-loop triage playbook.

Pull Wazuh alerts → extract/enrich IOCs → score → open/update cases → propose actions.
Lab-safe: never auto-executes containment.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from agentic_soc.triage import (  # noqa: E402
    build_summary,
    extract_iocs,
    score_alert,
    should_open_case,
)
from agentic_soc.tools import SocTools  # noqa: E402


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Agentic SOC closed-loop alert triage")
    p.add_argument("--min-level", type=int, default=5, help="Minimum Wazuh rule level (default 5)")
    p.add_argument("--limit", type=int, default=30, help="Alerts to fetch from indexer")
    p.add_argument("--max-cases", type=int, default=8, help="Max new cases to open this run")
    p.add_argument("--agent-name", default=None, help="Filter alerts by agent name")
    p.add_argument("--query", default=None, help="Optional OpenSearch query_string")
    p.add_argument("--enrich", action=argparse.BooleanOptionalAction, default=True)
    p.add_argument("--include-private-ips", action="store_true")
    p.add_argument("--dry-run", action="store_true", help="Score only; do not write cases")
    p.add_argument("--json-out", default=None, help="Write full run report JSON to path")
    return p.parse_args()


def _existing_alert_ids(tools: SocTools) -> set[str]:
    listed = tools.list_cases(limit=500)
    ids: set[str] = set()
    for c in listed.get("cases", []):
        aid = c.get("alert_id")
        if aid:
            ids.add(str(aid))
    return ids


async def _enrich_iocs(
    tools: SocTools,
    iocs: list[dict[str, str]],
    *,
    enabled: bool,
) -> list[dict[str, Any]]:
    if not enabled or not iocs:
        return []
    results: list[dict[str, Any]] = []
    # Cap VT calls per alert to stay within free-tier limits
    for item in iocs[:5]:
        results.append(await tools.enrich_ioc(item["ioc"], ioc_type=item["ioc_type"]))
    return results


async def triage_once(args: argparse.Namespace) -> dict[str, Any]:
    tools = SocTools()
    report: dict[str, Any] = {
        "params": {
            "min_level": args.min_level,
            "limit": args.limit,
            "max_cases": args.max_cases,
            "agent_name": args.agent_name,
            "query": args.query,
            "enrich": args.enrich,
            "dry_run": args.dry_run,
        },
        "alerts_fetched": 0,
        "results": [],
        "cases_opened": [],
    }

    print("=== Agentic SOC triage playbook ===\n")
    agents = await tools.list_agents()
    active = [a for a in agents.get("agents", []) if a.get("status") == "active"]
    print(f"Active agents: {len(active)} / {agents.get('total')}")
    for a in active:
        print(f"  - {a.get('name')} ({a.get('id')})")
    print()

    alerts_resp = await tools.list_alerts(
        limit=args.limit,
        min_level=args.min_level,
        agent_name=args.agent_name,
        query_string=args.query,
    )
    alerts = alerts_resp.get("alerts") or []
    report["alerts_fetched"] = len(alerts)
    print(
        f"Fetched {len(alerts)} alerts "
        f"(indexer total≈{alerts_resp.get('total')}, min_level={args.min_level})"
    )
    if not alerts:
        print("No alerts matched. Generate activity on the host, wait ~30s, re-run.")
        return report

    known = _existing_alert_ids(tools) if not args.dry_run else set()
    opened = 0

    for alert in alerts:
        alert_id = str(alert.get("id") or "")
        iocs = extract_iocs(alert, include_private_ips=args.include_private_ips)
        enrichments = await _enrich_iocs(tools, iocs, enabled=args.enrich)
        judgment = score_alert(alert, enrichments)
        gate = should_open_case(alert, judgment, sibling_alerts=alerts)
        summary = build_summary(alert, judgment, enrichments)

        item: dict[str, Any] = {
            "alert_id": alert_id,
            "agent": alert.get("agent"),
            "rule_id": alert.get("rule_id"),
            "rule_level": alert.get("rule_level"),
            "description": alert.get("description"),
            "iocs": iocs,
            "enrichments": [
                {k: e.get(k) for k in ("ioc", "ioc_type", "malicious", "suspicious", "found", "error")}
                for e in enrichments
            ],
            "judgment": judgment,
            "should_open_case": gate,
        }

        print("-" * 60)
        print(
            f"[{judgment['disposition']}] rule={alert.get('rule_id')} "
            f"lvl={alert.get('rule_level')} "
            f"agent={alert.get('agent')} | {alert.get('description')}"
        )
        print(
            f"  confidence={judgment['confidence']} score={judgment['score']} "
            f"action={judgment['recommended_action']} "
            f"open_case={gate['open']} ({gate['reason']})"
        )
        if iocs:
            ioc_preview = ", ".join(f"{i['ioc_type']}:{i['ioc']}" for i in iocs[:5])
            print(f"  iocs={ioc_preview}")

        if args.dry_run:
            item["case"] = None
            item["note"] = "dry-run"
            report["results"].append(item)
            continue

        if alert_id and alert_id in known:
            print("  skip: case already exists for this alert_id")
            item["case"] = {"skipped": "duplicate_alert_id"}
            report["results"].append(item)
            continue

        if not gate["open"]:
            print(f"  skip case: {gate['reason']} (still logged in report)")
            item["case"] = {"skipped": gate["reason"]}
            report["results"].append(item)
            continue

        if opened >= args.max_cases:
            print("  skip case: max-cases reached")
            item["case"] = {"skipped": "max_cases"}
            report["results"].append(item)
            continue

        case = tools.open_case(
            title=f"[{judgment['disposition']}] {alert.get('description') or 'alert'}",
            alert_id=alert_id or None,
            agent_name=alert.get("agent"),
            summary=summary,
            severity=judgment["severity"],
            recommended_action=judgment["recommended_action"],
        )
        tools.update_case(
            case["id"],
            disposition=judgment["disposition"],
            note=summary,
            author="agent_triage",
        )
        updated = tools.propose_action(
            case["id"],
            action=judgment["recommended_action"],
            rationale="; ".join(judgment.get("reasons") or ["auto-triage"]),
        )
        opened += 1
        if alert_id:
            known.add(alert_id)
        item["case"] = {
            "id": updated.get("id"),
            "status": updated.get("status"),
            "disposition": updated.get("disposition"),
            "recommended_action": updated.get("recommended_action"),
        }
        report["cases_opened"].append(item["case"])
        report["results"].append(item)
        print(f"  opened case #{updated.get('id')} disposition={updated.get('disposition')}")

    print()
    print(f"Done. Cases opened this run: {len(report['cases_opened'])}")
    print(f"Cases DB: {tools.settings.cases_path}")
    return report


async def main() -> int:
    args = _parse_args()
    report = await triage_once(args)
    if args.json_out:
        path = Path(args.json_out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2, default=str))
        print(f"Wrote report: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
