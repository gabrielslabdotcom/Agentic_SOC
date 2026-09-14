#!/usr/bin/env python3
"""Send a test case-opened message via Discord bot REST or webhook from .env."""

from __future__ import annotations

import asyncio
import sys
import uuid
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from agentic_soc.discord_notify import DiscordNotifier  # noqa: E402
from agentic_soc.tools import SocTools  # noqa: E402


async def main() -> int:
    n = DiscordNotifier()
    if not n.configured:
        print("Neither Discord bot nor webhook is configured in .env")
        print("  Bot (preferred, buttons): DISCORD_BOT_TOKEN + DISCORD_CHANNEL_ID")
        print("  Fallback: DISCORD_WEBHOOK_URL")
        return 1

    # Buttons need a real SQLite case id — never hardcode 0.
    tools = SocTools()
    alert_id = f"discord-check-{uuid.uuid4().hex[:12]}"
    opened = tools.open_case(
        title="[discord-check] Example port-scan (connectivity test)",
        alert_id=alert_id,
        agent_name="pop-os-native",
        summary=(
            "[discord-check]\nConnectivity test case for Discord outcome buttons. "
            "Safe to close with any analyst outcome (record-only)."
        ),
        severity="high",
        recommended_action="investigate_and_document",
        rule_id="100102",
        source_ip="192.0.2.10",
    )
    if opened.get("error"):
        print(f"Failed to open test case: {opened}")
        return 1
    case_id = int(opened["id"])
    tools.update_case(
        case_id,
        disposition="suspicious",
        note="[discord-check] sample triage for Discord connectivity test",
        author="discord-check",
    )
    tools.propose_action(
        case_id,
        action="investigate_and_document",
        rationale="discord connectivity test — aggregated port-scan fixture",
    )

    sample = {
        "id": case_id,
        "title": opened.get("title")
        or "[discord-check] Example port-scan (connectivity test)",
        "disposition": "suspicious",
        "severity": "high",
        "confidence": 0.7,
        "recommended_action": "investigate_and_document",
        "agent_name": "pop-os-native",
        "alert_id": alert_id,
        "rule_id": "100102",
        "rule_level": 8,
        "timestamp": "2026-09-07T00:00:00.000Z",
        "source_ip": "192.0.2.10",
        "iocs": [{"ioc": "192.0.2.10", "ioc_type": "ip"}],
        "reasons": ["aggregated port-scan / UFW correlation rule (100102)"],
        "enrichments": [],
        "full_log": "kernel: [UFW BLOCK] SRC=192.0.2.10 DST=198.51.100.1 DPT=3389",
    }
    result = await n.notify_case_opened(sample)
    print(result)
    print(f"Opened SQLite case #{case_id} (alert_id={alert_id}).")
    print(
        "Clicking an outcome button on this message will close that case "
        "(record-only — no containment)."
    )
    if result.get("via") == "bot":
        print("(posted via Gateway bot REST — buttons use the real case id)")
    elif result.get("via") == "webhook":
        print("(posted via webhook fallback — no buttons)")
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
