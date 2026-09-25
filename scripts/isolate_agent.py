#!/usr/bin/env python3
"""Break-glass host isolate / de-isolate.

Same gates as the dashboard: analyst role, HOST_ISOLATION_ENABLED, and --confirm.
Without --confirm this only prints the dry-run plan.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from agentic_soc.policy import ANALYST  # noqa: E402
from agentic_soc.tools import SocTools  # noqa: E402


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Plan or run Wazuh host isolation (HITL; off unless HOST_ISOLATION_ENABLED)"
    )
    p.add_argument("--agent", help="Wazuh agent name (required if --case-id is omitted)")
    p.add_argument("--case-id", type=int, help="Optional case to attach the audit note")
    p.add_argument("--action", choices=("isolate", "deisolate"), default="deisolate")
    p.add_argument(
        "--confirm",
        action="store_true",
        help="Actually send the active-response command. Omit to dry-run.",
    )
    p.add_argument("--author", default="isolate_agent.py")
    args = p.parse_args()
    if args.case_id is None and not (args.agent or "").strip():
        p.error("--agent or --case-id is required")
    return args


async def _run(args: argparse.Namespace) -> dict:
    tools = SocTools(role=ANALYST)
    if args.confirm:
        return await tools.execute_isolation(
            args.case_id,
            action=args.action,
            confirm=True,
            agent_name=args.agent,
            author=args.author,
        )
    return await tools.plan_isolation(
        case_id=args.case_id,
        agent_name=args.agent,
        record=args.case_id is not None,
        action=args.action,
    )


def main() -> int:
    args = _parse_args()
    result = asyncio.run(_run(args))
    print(json.dumps(result, indent=2, default=str))
    if result.get("error") == "policy_denied":
        return 2
    if args.confirm and not result.get("executed"):
        return 1
    if not args.confirm and not result.get("allowed"):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
