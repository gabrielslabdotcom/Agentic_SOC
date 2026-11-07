#!/usr/bin/env python3
"""Health check against live Wazuh manager API + indexer."""

from __future__ import annotations

import asyncio
import re
import sys
from pathlib import Path

# Allow running without editable install: PYTHONPATH=src or repo-root/scripts layout
_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from agentic_soc.config import get_settings  # noqa: E402
from agentic_soc.wazuh_client import WazuhClient  # noqa: E402

# Lab target; bump when the stack is intentionally upgraded.
EXPECTED_VERSION = "4.14.10"

_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+)")


def _parse_version(raw: str | None) -> str | None:
    if not raw:
        return None
    match = _VERSION_RE.search(raw)
    return match.group(1) if match else None


def _version_behind(current: str | None, expected: str) -> bool:
    if not current:
        return True
    try:
        cur = tuple(int(p) for p in current.split("."))
        exp = tuple(int(p) for p in expected.split("."))
    except ValueError:
        return current != expected
    return cur < exp


async def main() -> int:
    settings = get_settings()
    client = WazuhClient(settings)
    print(f"API URL:     {settings.wazuh_api_url}")
    print(f"Indexer URL: {settings.wazuh_indexer_url}")
    print(f"Expected:    Wazuh {EXPECTED_VERSION}")
    print()

    try:
        token = await client.authenticate()
        print(f"[ok] API auth — token length {len(token)}")
    except Exception as exc:
        print(f"[fail] API auth: {exc}")
        return 1

    behind: list[str] = []
    try:
        info = await client._api_get("/manager/info")  # noqa: SLF001
        items = (info.get("data") or {}).get("affected_items") or []
        mgr = items[0] if items else {}
        mgr_ver_raw = str(mgr.get("version") or "")
        mgr_ver = _parse_version(mgr_ver_raw)
        print(f"[ok] Manager version: {mgr_ver_raw or 'unknown'}")
        if _version_behind(mgr_ver, EXPECTED_VERSION):
            behind.append(f"manager {mgr_ver_raw or '?'}")
            print(f"[warn] Manager behind expected {EXPECTED_VERSION}")
    except Exception as exc:
        print(f"[fail] Manager info: {exc}")
        return 1

    try:
        summary = await client.agents_summary()
        print(f"[ok] Agents summary: {summary}")
        agents = await client.list_agents(limit=100)
        print(f"[ok] Agents listed: {agents['total']}")
        for a in agents["agents"]:
            name = a.get("name")
            status = a.get("status")
            ver_raw = str(a.get("version") or "")
            ver = _parse_version(ver_raw)
            flag = ""
            if _version_behind(ver, EXPECTED_VERSION):
                behind.append(f"{name} {ver_raw or '?'} ({status})")
                flag = " [behind]"
            print(
                f"     - {a.get('id')} {name} status={status} "
                f"version={ver_raw or 'n/a'} ip={a.get('ip')}{flag}"
            )
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
    if behind:
        print(f"[warn] {len(behind)} component(s) behind {EXPECTED_VERSION}:")
        for item in behind:
            print(f"     - {item}")
        print("Wazuh API/indexer reachable; upgrade stragglers when ready.")
        return 0

    print(f"Wazuh stack healthy and at {EXPECTED_VERSION} (or newer) from this workstation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
