#!/usr/bin/env python3
"""Demo: pull recent alerts, open a case, propose a lab-safe action."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from agentic_soc.tools import SocTools  # noqa: E402


def _severity_for_level(level: int | None) -> str:
    if level is None:
        return "medium"
    if level >= 12:
        return "critical"
    if level >= 7:
        return "high"
    if level >= 4:
        return "medium"
    return "low"


async def main() -> int:
    tools = SocTools()

    print("=== Agentic SOC triage demo ===\n")

    agents = await tools.list_agents(limit=20)
    print(f"Agents ({agents['total']}):")
    for a in agents["agents"]:
        print(f"  - [{a.get('status')}] {a.get('name')} ({a.get('id')}) {a.get('ip')}")
    print()

    alerts = await tools.list_alerts(limit=10, min_level=0)
    print(f"Recent alerts (returned={alerts['count']}, total≈{alerts['total']}):")
    if not alerts["alerts"]:
        print("  (no alerts yet — manager/agent may still be warming up)")
        case = tools.open_case(
            title="Lab warm-up: no alerts yet",
            summary="Indexer returned zero alerts. Case opened to exercise case memory.",
            severity="low",
            recommended_action="Wait for agent telemetry; re-run triage_demo.py",
        )
    else:
        for alert in alerts["alerts"][:5]:
            print(
                f"  - id={alert.get('id')} lvl={alert.get('rule_level')} "
                f"agent={alert.get('agent')} | {alert.get('description')}"
            )
        top = alerts["alerts"][0]
        level = top.get("rule_level")
        case = tools.open_case(
            title=f"Triage: {top.get('description') or 'alert'}",
            alert_id=top.get("id"),
            agent_name=top.get("agent"),
            summary=(
                f"Auto-opened from triage demo. rule_id={top.get('rule_id')} "
                f"level={level} ts={top.get('timestamp')}"
            ),
            severity=_severity_for_level(level if isinstance(level, int) else None),
            recommended_action="Investigate alert context; no containment without human approval",
        )
        print()
        print(f"Opened case from alert id={top.get('id')}")

    print()
    print("Case:")
    print(json.dumps({k: v for k, v in case.items() if k != "notes"}, indent=2))

    updated = tools.propose_action(
        case["id"],
        action="investigate_and_document",
        rationale="Lab demo: recommend investigation only; do not isolate host automatically.",
    )
    print()
    print(f"Proposed action on case {case['id']}:")
    print(f"  recommended_action={updated.get('recommended_action')}")
    notes = updated.get("notes") or []
    if notes:
        print(f"  latest note:\n{notes[-1].get('note')}")

    listed = tools.list_cases(limit=5)
    print()
    print(f"Open cases in store ({listed['count']} shown):")
    for c in listed["cases"]:
        print(f"  - #{c['id']} [{c['status']}/{c['severity']}] {c['title']}")

    print()
    print("Demo complete. Cases DB:", tools.settings.cases_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
