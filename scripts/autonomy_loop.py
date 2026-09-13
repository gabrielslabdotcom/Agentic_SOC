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
    is_auto_close_noise,
    score_alert,
    should_open_case,
)
from agentic_soc.tools import SocTools  # noqa: E402

LOG = logging.getLogger("autonomy_loop")
_STOP = asyncio.Event()


def stop_requested() -> bool:
    """True after SIGTERM/SIGINT — checked between alerts so a cycle can exit early."""
    return _STOP.is_set()


def max_alert_timestamp(alerts: list[dict[str, Any]]) -> str | None:
    """Latest ISO-ish timestamp in a batch (lexicographic max of non-empty strings)."""
    stamps = [str(a.get("timestamp") or "").strip() for a in alerts]
    stamps = [s for s in stamps if s]
    return max(stamps) if stamps else None


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Agentic SOC autonomous triage loop")
    p.add_argument("--interval", type=int, default=int(os.environ.get("AUTONOMY_INTERVAL", "120")))
    # Default 8: skip level-5 UFW block floods. Auth L5 is OR'd in via --include-auth.
    p.add_argument("--min-level", type=int, default=int(os.environ.get("AUTONOMY_MIN_LEVEL", "8")))
    p.add_argument(
        "--include-auth",
        action=argparse.BooleanOptionalAction,
        default=os.environ.get("AUTONOMY_INCLUDE_AUTH", "true").lower()
        in ("1", "true", "yes"),
        help="Also fetch sshd/PAM auth failures at --auth-min-level without lowering min-level",
    )
    p.add_argument(
        "--auth-min-level",
        type=int,
        default=int(os.environ.get("AUTONOMY_AUTH_MIN_LEVEL", "5")),
    )
    p.add_argument(
        "--feedback-skip",
        action=argparse.BooleanOptionalAction,
        default=os.environ.get("AUTONOMY_FEEDBACK_SKIP", "true").lower()
        in ("1", "true", "yes"),
        help="Skip opening when the same rule_id+source_ip was recently rejected",
    )
    p.add_argument(
        "--auto-close-noise",
        action=argparse.BooleanOptionalAction,
        default=os.environ.get("AUTONOMY_AUTO_CLOSE_NOISE", "true").lower()
        in ("1", "true", "yes"),
        help="Auto-close informational/FP cases without Discord/Cursor (still no containment)",
    )
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
        "auto_closed": 0,
        "discord": [],
        "cursor_agent": [],
    }

    try:
        exclude = [RULE_UFW_BLOCK] if args.exclude_ufw_blocks else None
        since = (state.get("last_seen_timestamp") or "").strip() or None
        alerts_resp = await tools.list_alerts(
            limit=args.limit,
            min_level=args.min_level,
            agent_name=args.agent_name or None,
            exclude_rule_ids=exclude,
            since=since,
            include_auth_min_level=args.auth_min_level if args.include_auth else None,
        )
    except Exception as exc:  # noqa: BLE001
        LOG.exception("Failed to fetch alerts: %s", exc)
        report["error"] = str(exc)
        return report

    alerts = alerts_resp.get("alerts") or []
    report["alerts_fetched"] = len(alerts)
    report["since"] = since
    LOG.info(
        "cycle: fetched=%s total≈%s min_level=%s include_auth=%s auth_min=%s agent=%s exclude_ufw=%s since=%s",
        len(alerts),
        alerts_resp.get("total"),
        args.min_level,
        bool(args.include_auth),
        args.auth_min_level if args.include_auth else None,
        args.agent_name,
        bool(args.exclude_ufw_blocks),
        since,
    )

    opened = 0
    batch_complete = True
    for alert in alerts:
        if stop_requested():
            batch_complete = False
            LOG.info("stop requested — leaving remaining alerts for the next start")
            break
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
        src_ip = extract_source_ip(alert)
        rule_id = str(alert.get("rule_id") or "")
        if args.feedback_skip:
            fb = tools.rejected_similar(rule_id=rule_id or None, source_ip=src_ip)
            if fb.get("skip"):
                LOG.info(
                    "skip feedback-rejected rule=%s src=%s count=%s",
                    rule_id,
                    src_ip,
                    fb.get("count"),
                )
                report["skipped"] += 1
                continue

        enrichments = await _enrich(tools, iocs, args.enrich)
        if enrichments:
            judgment = score_alert(alert, enrichments)
        noise = is_auto_close_noise(alert, judgment, enrichments=enrichments)
        auto_noise = bool(args.auto_close_noise) and bool(noise.get("close"))
        if not auto_noise and opened >= args.max_cases:
            LOG.warning("max-cases (%s) reached this cycle", args.max_cases)
            break
        summary = f"[autonomy_loop]\n{build_summary(alert, judgment, enrichments)}"
        case = tools.open_case(
            title=f"[auto][{judgment['disposition']}] {alert.get('description') or 'alert'}",
            alert_id=alert_id or None,
            agent_name=alert.get("agent"),
            summary=summary,
            severity=judgment["severity"],
            recommended_action=judgment["recommended_action"],
            rule_id=rule_id or None,
            source_ip=src_ip,
        )
        if case.get("duplicate"):
            LOG.info("duplicate alert_id=%s already case #%s — skip notify", alert_id, case.get("id"))
            report["skipped"] += 1
            if alert_id:
                known_cases.add(alert_id)
            continue
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
        try:
            corr = tools.correlate_alert(
                alert,
                case_id=case["id"],
                alert_id=alert_id or None,
            )
            LOG.info(
                "correlated case #%s entities=%s",
                case["id"],
                corr.get("count"),
            )
        except Exception as exc:  # noqa: BLE001
            LOG.warning("entity correlation failed case #%s: %s", case["id"], exc)

        if auto_noise:
            closed = tools.auto_close_noise(
                case["id"],
                note=f"{noise.get('reason')}: {judgment['disposition']}",
                author="autonomy_loop",
            )
            report["auto_closed"] += 1
            if alert_id:
                known_cases.add(alert_id)
            LOG.info(
                "auto-closed noise case #%s disposition=%s reason=%s | %s",
                closed.get("id"),
                judgment["disposition"],
                noise.get("reason"),
                alert.get("description"),
            )
            continue

        if src_ip:
            try:
                plan = tools.plan_containment(
                    source_ip=src_ip,
                    case_id=case["id"],
                    record=True,
                )
                LOG.info(
                    "containment plan case #%s allowed=%s ip=%s",
                    case["id"],
                    plan.get("allowed"),
                    src_ip,
                )
            except Exception as exc:  # noqa: BLE001
                LOG.warning("containment plan failed case #%s: %s", case["id"], exc)

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
                "3) Open http://192.168.50.254:8080/ — False Positive / Benign / "
                "Informational / Duplicate skip repeats; Confirmed Compromise does not. "
                "None run containment."
            ),
        }
        report["cases_opened"].append(case_info)
        LOG.info(
            "opened case #%s disposition=%s rule=%s level=%s",
            updated.get("id"),
            updated.get("disposition"),
            alert.get("rule_id"),
            alert.get("rule_level"),
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
    # Only advance the cursor after a full batch so SIGTERM cannot skip unprocessed alerts.
    if batch_complete:
        newest = max_alert_timestamp(alerts)
        if newest:
            prev = (state.get("last_seen_timestamp") or "").strip()
            state["last_seen_timestamp"] = max(prev, newest) if prev else newest
    state["last_cycle"] = {
        "ts": report["ts"],
        "alerts_fetched": report["alerts_fetched"],
        "opened": opened,
        "skipped": report["skipped"],
        "auto_closed": report["auto_closed"],
        "since": since,
        "last_seen_timestamp": state.get("last_seen_timestamp"),
        "truncated": bool(since) and len(alerts) >= args.limit,
        "batch_complete": batch_complete,
    }
    return report


def _install_signal_handlers() -> None:
    def _handler(signum: int, _frame: Any) -> None:
        LOG.info("received signal %s — stopping after the current alert", signum)
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
                "cycle done: fetched=%s opened=%s auto_closed=%s skipped=%s",
                report.get("alerts_fetched"),
                len(report.get("cases_opened") or []),
                report.get("auto_closed"),
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
