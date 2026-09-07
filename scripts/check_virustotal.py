#!/usr/bin/env python3
"""Verify VirusTotal API key works (does not print the key)."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from agentic_soc.config import get_settings  # noqa: E402
from agentic_soc.enrichment import VirusTotalClient  # noqa: E402


async def main() -> int:
    settings = get_settings()
    client = VirusTotalClient(settings)
    configured = client.configured
    print(f"VIRUSTOTAL_API_KEY configured: {configured}")
    if configured:
        print(f"VIRUSTOTAL_API_KEY length: {len(settings.virustotal_api_key.strip())}")

    result = await client.verify_auth()
    if result.get("ok"):
        print(f"[ok] {result.get('message')}")
        return 0

    print(f"[fail] {result.get('error')} (status={result.get('status_code')})")
    return 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
