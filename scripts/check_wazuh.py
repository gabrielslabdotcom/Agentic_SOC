#!/usr/bin/env python3
"""Health check against live Wazuh manager API + indexer."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# Allow running without editable install: PYTHONPATH=src or repo-root/scripts layout
_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from agentic_soc.config import get_settings  # noqa: E402
from agentic_soc.wazuh_client import WazuhClient  # noqa: E402


async def main() -> int:
    settings = get_settings()
    client = WazuhClient(settings)
    print(f"API URL:     {settings.wazuh_api_url}")
    print(f"Indexer URL: {settings.wazuh_indexer_url}")
    print()

    try:
        token = await client.authenticate()
        print(f"[ok] API auth — token length {len(token)}")
    except Exception as exc:
        print(f"[fail] API auth: {exc}")
        return 1

    try:
        summary = await client.agents_summary()
        print(f"[ok] Agents summary: {summary}")
        agents = await client.list_agents(limit=20)
        print(f"[ok] Agents listed: {agents['total']}")
        for a in agents["agents"][:10]:
            print(f"     - {a.get('id')} {a.get('name')} status={a.get('status')} ip={a.get('ip')}")
    except Exception as exc:
        print(f"[fail] Agents: {exc}")
        return 1

    try:
        alerts = await client.list_alerts(limit=5)
        print(f"[ok] Indexer alerts — total≈{alerts['total']}, returned={alerts['count']}")
        for alert in alerts["alerts"][:3]:
            print(
                f"     - lvl={alert.get('rule_level')} "
                f"agent={alert.get('agent')} "
                f"{alert.get('description')}"
            )
    except Exception as exc:
        print(f"[fail] Indexer alerts: {exc}")
        return 1

    print()
    print("Wazuh stack looks healthy from this workstation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
