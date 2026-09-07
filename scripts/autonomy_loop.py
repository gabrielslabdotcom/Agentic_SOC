#!/usr/bin/env python3
"""
Autonomous triage loop for Pop!_OS (systemd service).

Polls Wazuh → scores alerts → opens cases → Discord notify → optional Cursor
cloud propose-only investigation → propose_action only.
Never executes containment.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from agentic_soc.cursor_agent import maybe_kick_after_case_open  # noqa: E402
from agentic_soc.discord_notify import DiscordNotifier  # noqa: E402
from agentic_soc.triage import (  # noqa: E402
    RULE_UFW_BLOCK,
    build_summary,
    extract_iocs,
    extract_source_ip,
    score_alert,
    should_open_case,
)
from agentic_soc.tools import SocTools  # noqa: E402

LOG = logging.getLogger("autonomy_loop")
_STOP = asyncio.Event()


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Agentic SOC autonomous triage loop")
    p.add_argument("--interval", type=int, default=int(os.environ.get("AUTONOMY_INTERVAL", "120")))
    # Default 8: skip level-5 UFW block floods; auth (often L5) needs --min-level 5 if desired
    p.add_argument("--min-level", type=int, default=int(os.environ.get("AUTONOMY_MIN_LEVEL", "8")))
    p.add_argument("--limit", type=int, default=int(os.environ.get("AUTONOMY_LIMIT", "40")))
    p.add_argument("--max-cases", type=int, default=int(os.environ.get("AUTONOMY_MAX_CASES", "10")))
    p.add_argument(
        "--agent-name",
        default=os.environ.get("AUTONOMY_AGENT_NAME", "pop-os-native"),
    )
    p.add_argument(
        "--exclude-ufw-blocks",
        action=argparse.BooleanOptionalAction,
        default=os.environ.get("AUTONOMY_EXCLUDE_UFW_BLOCKS", "true").lower()
        in ("1", "true", "yes"),
        help="Exclude lone UFW BLOCK rule 100100 from the fetch (prefer aggregates)",
    )
    p.add_argument(
        "--enrich",
        action=argparse.BooleanOptionalAction,
        default=os.environ.get("AUTONOMY_ENRICH", "true").lower() in ("1", "true", "yes"),
    )
    p.add_argument(
        "--discord",
        action=argparse.BooleanOptionalAction,
        default=os.environ.get("AUTONOMY_DISCORD", "true").lower() in ("1", "true", "yes"),
    )
    p.add_argument(
        "--cursor-agent",
        action=argparse.BooleanOptionalAction,
        default=os.environ.get("AUTONOMY_CURSOR_AGENT", "false").lower()
        in ("1", "true", "yes"),
        help="After opening a case, kick a Cursor cloud propose-only investigation",
    )
    p.add_argument(
        "--cursor-dry-run",
        action="store_true",
        help="Print Cursor investigation prompt instead of calling the SDK",
    )
    p.add_argument(
        "--state-file",
        default=os.environ.get("AUTONOMY_STATE_FILE", str(_ROOT / "data" / "autonomy_state.json")),
    )
    p.add_argument("--once", action="store_true", help="Run a single cycle and exit")
    p.add_argument("--log-level", default=os.environ.get("AUTONOMY_LOG_LEVEL", "INFO"))
    return p.parse_args()


def _load_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"seen_alert_ids": [], "cycles": 0, "cases_opened_total": 0}
    try:
        return json.loads(path.read_text())
    except Exception:  # noqa: BLE001
        return {"seen_alert_ids": [], "cycles": 0, "cases_opened_total": 0}


def _save_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    seen = list(dict.fromkeys(state.get("seen_alert_ids") or []))[-5000:]
    state["seen_alert_ids"] = seen
    state["updated_at"] = datetime.now(timezone.utc).isoformat()
    path.write_text(json.dumps(state, indent=2))


def _existing_case_alert_ids(tools: SocTools) -> set[str]:
    ids: set[str] = set()
    for c in tools.list_cases(limit=1000).get("cases", []):
        aid = c.get("alert_id")
        if aid:
            ids.add(str(aid))
    return ids


async def _enrich(tools: SocTools, iocs: list[dict[str, str]], enabled: bool) -> list[dict[str, Any]]:
    if not enabled or not iocs:
        return []
    out: list[dict[str, Any]] = []
    for item in iocs[:3]:
        try:
            out.append(await tools.enrich_ioc(item["ioc"], ioc_type=item["ioc_type"]))
        except Exception as exc:  # noqa: BLE001
            out.append({"ioc": item["ioc"], "error": str(exc)})
    return out


async def run_cycle(args: argparse.Namespace, state: dict[str, Any]) -> dict[str, Any]:
    tools = SocTools()
    discord = DiscordNotifier(tools.settings)
    seen = set(state.get("seen_alert_ids") or [])
    known_cases = _existing_case_alert_ids(tools)
    report: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "alerts_fetched": 0,
        "cases_opened": [],
        "skipped": 0,
        "discord": [],
        "cursor_agent": [],
    }

    try:
        exclude = [RULE_UFW_BLOCK] if args.exclude_ufw_blocks else None
        alerts_resp = await tools.list_alerts(
            limit=args.limit,
            min_level=args.min_level,
            agent_name=args.agent_name or None,
            exclude_rule_ids=exclude,
        )
    except Exception as exc:  # noqa: BLE001
        LOG.exception("Failed to fetch alerts: %s", exc)
        report["error"] = str(exc)
        return report

    alerts = alerts_resp.get("alerts") or []
    report["alerts_fetched"] = len(alerts)
    LOG.info(
        "cycle: fetched=%s total≈%s min_level=%s agent=%s exclude_ufw=%s",
        len(alerts),
        alerts_resp.get("total"),
        args.min_level,
        args.agent_name,
        bool(args.exclude_ufw_blocks),
    )

    opened = 0
    for alert in alerts:
        alert_id = str(alert.get("id") or "")
        if alert_id and alert_id in seen:
            report["skipped"] += 1
            continue
        if alert_id:
            seen.add(alert_id)

        iocs = extract_iocs(alert)
        # Score first without VT — only enrich when we will open a case
        judgment = score_alert(alert, [])
        gate = should_open_case(alert, judgment, sibling_alerts=alerts)

        if not gate.get("open"):
            report["skipped"] += 1
            continue
        if alert_id and alert_id in known_cases:
            report["skipped"] += 1
            continue
        if opened >= args.max_cases:
            LOG.warning("max-cases (%s) reached this cycle", args.max_cases)
            break

        enrichments = await _enrich(tools, iocs, args.enrich)
        if enrichments:
            judgment = score_alert(alert, enrichments)
        summary = f"[autonomy_loop]\n{build_summary(alert, judgment, enrichments)}"
        case = tools.open_case(
            title=f"[auto][{judgment['disposition']}] {alert.get('description') or 'alert'}",
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
            author="autonomy_loop",
        )
        updated = tools.propose_action(
            case["id"],
            action=judgment["recommended_action"],
            rationale="; ".join(judgment.get("reasons") or ["autonomous triage"]),
        )
        opened += 1
        if alert_id:
            known_cases.add(alert_id)

        case_info = {
            "id": updated.get("id"),
            "title": updated.get("title") or case.get("title"),
            "disposition": updated.get("disposition"),
            "severity": updated.get("severity") or judgment["severity"],
            "confidence": judgment.get("confidence"),
            "recommended_action": updated.get("recommended_action"),
            "agent_name": updated.get("agent_name") or alert.get("agent"),
            "alert_id": alert_id,
            "description": alert.get("description"),
            "rule_id": alert.get("rule_id"),
            "rule_level": alert.get("rule_level"),
            "timestamp": alert.get("timestamp"),
            "full_log": alert.get("full_log"),
            "source_ip": extract_source_ip(alert),
            "iocs": iocs,
            "reasons": judgment.get("reasons") or [],
            "enrichments": [
                {
                    "ioc": e.get("ioc"),
                    "ioc_type": e.get("ioc_type"),
                    "malicious": e.get("malicious"),
                    "suspicious": e.get("suspicious"),
                    "error": e.get("error"),
                }
                for e in (enrichments or [])
            ],
            "analyst_next_steps": (
                "1) Open Wazuh dashboard and confirm this alert/rule\n"
                "2) Check source IP / IOCs (lab scan vs unknown)\n"
                "3) Approve to document, or reject if noise — no containment runs"
            ),
        }
        report["cases_opened"].append(case_info)
        LOG.info(
            "opened case #%s disposition=%s | %s",
            updated.get("id"),
            updated.get("disposition"),
            alert.get("description"),
        )

        if args.discord and discord.configured:
            try:
                n = await discord.notify_case_opened(case_info)
                report["discord"].append(n)
                if not n.get("ok"):
                    LOG.warning("discord notify failed: %s", n)
            except Exception as exc:  # noqa: BLE001
                LOG.warning("discord notify error: %s", exc)
        elif args.discord and not discord.configured:
            LOG.debug("DISCORD_WEBHOOK_URL not set — skipping notify")

        # Mac-offline path: Cursor cloud propose-only investigation (fail soft)
        if args.cursor_agent or args.cursor_dry_run:
            try:
                c = maybe_kick_after_case_open(
                    case_info,
                    enabled=True if args.cursor_agent or args.cursor_dry_run else None,
                    dry_run=bool(args.cursor_dry_run),
                )
                report["cursor_agent"].append(
                    {
                        "case_id": case_info.get("id"),
                        "ok": c.get("ok"),
                        "skipped": c.get("skipped"),
                        "dry_run": c.get("dry_run"),
                        "error": c.get("error"),
                        "started": c.get("started"),
                    }
                )
                if c.get("dry_run") and c.get("prompt"):
                    LOG.info(
                        "cursor dry-run prompt for case #%s:\n%s",
                        case_info.get("id"),
                        c["prompt"],
                    )
                elif not c.get("ok") and not c.get("skipped"):
                    LOG.warning("cursor agent kick failed: %s", c.get("error"))
            except Exception as exc:  # noqa: BLE001
                LOG.warning("cursor agent hook error: %s", exc)
                report["cursor_agent"].append(
                    {"case_id": case_info.get("id"), "ok": False, "error": str(exc)}
                )

    state["seen_alert_ids"] = list(seen)
    state["cycles"] = int(state.get("cycles") or 0) + 1
    state["cases_opened_total"] = int(state.get("cases_opened_total") or 0) + opened
    state["last_cycle"] = {
        "ts": report["ts"],
        "alerts_fetched": report["alerts_fetched"],
        "opened": opened,
        "skipped": report["skipped"],
    }
    return report


def _install_signal_handlers() -> None:
    def _handler(signum: int, _frame: Any) -> None:
        LOG.info("received signal %s — stopping after current cycle", signum)
        _STOP.set()

    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)


async def main_async(args: argparse.Namespace) -> int:
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    _install_signal_handlers()
    state_path = Path(args.state_file)
    state = _load_state(state_path)
    LOG.info(
        "autonomy_loop starting interval=%ss once=%s discord=%s cursor_agent=%s dry_run=%s state=%s",
        args.interval,
        args.once,
        args.discord,
        args.cursor_agent,
        args.cursor_dry_run,
        state_path,
    )

    while not _STOP.is_set():
        try:
            report = await run_cycle(args, state)
            _save_state(state_path, state)
            LOG.info(
                "cycle done: fetched=%s opened=%s skipped=%s",
                report.get("alerts_fetched"),
                len(report.get("cases_opened") or []),
                report.get("skipped"),
            )
        except Exception:  # noqa: BLE001
            LOG.exception("cycle failed")
            _save_state(state_path, state)

        if args.once or _STOP.is_set():
            break
        try:
            await asyncio.wait_for(_STOP.wait(), timeout=max(5, args.interval))
        except asyncio.TimeoutError:
            pass

    LOG.info("autonomy_loop stopped")
    return 0


def main() -> int:
    return asyncio.run(main_async(_parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
