#!/usr/bin/env python3
"""Send a test message to DISCORD_WEBHOOK_URL from .env."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from agentic_soc.discord_notify import DiscordNotifier  # noqa: E402


async def main() -> int:
    n = DiscordNotifier()
    if not n.configured:
        print("DISCORD_WEBHOOK_URL is not set in .env")
        print("Discord → Server → Channel → Edit → Integrations → Webhooks → New Webhook → Copy URL")
        return 1
    sample = {
        "id": 0,
        "title": "[auto][suspicious] Example port-scan (webhook test)",
        "disposition": "suspicious",
        "severity": "high",
        "confidence": 0.7,
        "recommended_action": "investigate_and_document",
        "agent_name": "pop-os-native",
        "alert_id": "test-alert-id",
        "rule_id": "100102",
        "rule_level": 8,
        "timestamp": "2026-09-07T00:00:00.000Z",
        "source_ip": "192.168.153.148",
        "iocs": [{"ioc": "192.168.153.148", "ioc_type": "ip"}],
        "reasons": ["aggregated port-scan / UFW correlation rule (100102)"],
        "enrichments": [],
        "full_log": "kernel: [UFW BLOCK] SRC=192.168.153.148 DST=192.168.50.254 DPT=3389",
    }
    result = await n.notify_case_opened(sample)
    print(result)
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
