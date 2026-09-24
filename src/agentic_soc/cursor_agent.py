"""Optional Cursor cloud investigation hook (propose-only, Mac-offline path).

Triggered from Pop!_OS ``autonomy_loop`` after a case is opened. Uses the
Cursor Python SDK (``cursor-sdk``) cloud runtime — not Automations, not local
Hydra. Failures are logged and never raise into the autonomy cycle.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
from typing import Any, Optional

from agentic_soc.config import Settings, get_settings

LOG = logging.getLogger("agentic_soc.cursor_agent")

DEFAULT_MODEL = "composer-2.5"
DEFAULT_STARTING_REF = "main"
INVESTIGATION_AUTHOR = "cursor_cloud_agent"
MEANING_AUTHOR = "incident_investigator"
NOTE_PREFIX = "[cursor_investigation]"
MEANING_PREFIX = "[incident_meaning]"
MAX_NOTE_CHARS = 50000
_FORBIDDEN_PACKET_KEYS = frozenset(
    {"approve_case", "execute_containment", "propose_action", "auto_execute"}
)


def _truthy(value: Optional[str], default: bool = False) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def cursor_agent_enabled(settings: Optional[Settings] = None) -> bool:
    """Return True when the cloud investigation hook should run."""
    settings = settings or get_settings()
    # Explicit env wins over Settings default so systemd/EnvironmentFile work
    # even before Settings fields are added / reloaded.
    flag = os.environ.get("AUTONOMY_CURSOR_AGENT")
    if flag is not None and flag != "":
        enabled = _truthy(flag)
    else:
        enabled = bool(settings.autonomy_cursor_agent)
    if not enabled:
        return False
    api_key = (settings.cursor_api_key or os.environ.get("CURSOR_API_KEY") or "").strip()
    if not api_key:
        LOG.warning("AUTONOMY_CURSOR_AGENT enabled but CURSOR_API_KEY is empty — skipping")
        return False
    return True


def _clip(text: str, limit: int = 240) -> str:
    cleaned = " ".join((text or "").split())
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 1] + "…"


def _slim_alert(alert: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(alert, dict):
        return {}
    if alert.get("error"):
        return {"error": str(alert.get("error"))}
    return {
        "id": alert.get("id"),
        "timestamp": alert.get("timestamp"),
        "rule_id": alert.get("rule_id"),
        "rule_level": alert.get("rule_level"),
        "description": _clip(str(alert.get("description") or ""), 180),
        "agent": alert.get("agent") or alert.get("agent_name"),
        "evidence": _clip(str(alert.get("full_log") or ""), 200),
    }


def should_explain_incident(*, opened_new: bool, severity_rose: bool) -> bool:
    """Explain when an incident opens or an attached alert raises severity."""
    return bool(opened_new or severity_rose)


async def build_incident_packet(
    tools: Any,
    *,
    case_id: int,
    alert_id: Optional[str] = None,
    agent_name: Optional[str] = None,
    enrichments: Optional[list[dict[str, Any]]] = None,
    nearby_limit: int = 5,
) -> dict[str, Any]:
    """Read-only context for one incident. No approve, execute, or propose."""
    case = tools.get_case(int(case_id))
    if case.get("error"):
        return {"ok": False, "error": case.get("error"), "case_id": case_id, "tools_used": ["get_case"]}

    related = tools.find_related(case_id=int(case_id))
    related_cases = []
    for item in (related.get("related_cases") or [])[:8]:
        if not isinstance(item, dict):
            continue
        related_cases.append(
            {
                "id": item.get("id"),
                "title": _clip(str(item.get("title") or ""), 120),
                "status": item.get("status"),
                "disposition": item.get("disposition"),
                "severity": item.get("severity"),
                "rule_id": item.get("rule_id"),
                "source_ip": item.get("source_ip"),
            }
        )

    trigger: dict[str, Any] = {}
    if alert_id:
        try:
            trigger = _slim_alert(await tools.get_alert(str(alert_id)))
        except Exception as exc:  # noqa: BLE001
            trigger = {"id": alert_id, "error": str(exc)}

    nearby: list[dict[str, Any]] = []
    agent = (agent_name or case.get("agent_name") or "").strip() or None
    try:
        listed = await tools.list_alerts(limit=max(1, nearby_limit), agent_name=agent)
        for item in (listed.get("alerts") or [])[:nearby_limit]:
            slim = _slim_alert(item)
            if slim.get("id") and str(slim.get("id")) == str(alert_id or ""):
                continue
            nearby.append(slim)
    except Exception as exc:  # noqa: BLE001
        nearby = [{"error": str(exc)}]

    brief = case.get("brief") if isinstance(case.get("brief"), dict) else {}
    packet = {
        "ok": True,
        "case_id": int(case_id),
        "title": case.get("title"),
        "disposition": case.get("disposition"),
        "severity": case.get("severity"),
        "rule_id": case.get("rule_id"),
        "source_ip": case.get("source_ip"),
        "actor_user": case.get("actor_user") or (brief.get("actors") or {}).get("user"),
        "agent_name": case.get("agent_name"),
        "alert_id": alert_id or case.get("alert_id"),
        "alert_count": case.get("alert_count") or 1,
        "brief": {
            "headline": brief.get("headline"),
            "actors": brief.get("actors") or {},
            "why": (brief.get("why") or [])[:2],
            "evidence": brief.get("evidence"),
            "vt": brief.get("vt"),
            "do_next": (brief.get("do_next") or [])[:3],
        },
        "related_case_ids": [item.get("id") for item in related_cases if item.get("id") is not None],
        "related_cases": related_cases,
        "trigger_alert": trigger,
        "nearby_alerts": nearby[:nearby_limit],
        "enrichments": [
            {
                "ioc": e.get("ioc"),
                "malicious": e.get("malicious"),
                "suspicious": e.get("suspicious"),
                "error": e.get("error"),
            }
            for e in (enrichments or [])[:4]
            if isinstance(e, dict)
        ],
        "tools_used": ["get_case", "find_related", "get_alert", "list_alerts"],
    }
    return {k: v for k, v in packet.items() if k not in _FORBIDDEN_PACKET_KEYS}


def render_meaning_note(packet: dict[str, Any]) -> str:
    """Deterministic four-part explanation. Containment stays manual."""
    brief = packet.get("brief") if isinstance(packet.get("brief"), dict) else {}
    actors = brief.get("actors") if isinstance(brief.get("actors"), dict) else {}
    who = []
    if actors.get("user") or packet.get("actor_user"):
        who.append(f"user {actors.get('user') or packet.get('actor_user')}")
    if actors.get("source_ip") or packet.get("source_ip"):
        who.append(f"source {actors.get('source_ip') or packet.get('source_ip')}")
    if actors.get("agent") or packet.get("agent_name"):
        who.append(f"host {actors.get('agent') or packet.get('agent_name')}")
    subject = ", ".join(who) or "this host"
    headline = brief.get("headline") or packet.get("title") or "Incident"
    disposition = packet.get("disposition") or "unscored"
    count = packet.get("alert_count") or 1
    related_ids = packet.get("related_case_ids") or []
    related_text = ", ".join(f"#{cid}" for cid in related_ids) or "none"
    why = "; ".join(str(r) for r in (brief.get("why") or []) if r) or "triage opened or updated this incident"
    evidence = brief.get("evidence") or (packet.get("trigger_alert") or {}).get("evidence") or "none"
    vt = brief.get("vt") or ""
    if not vt:
        bits = []
        for item in packet.get("enrichments") or []:
            if item.get("error"):
                bits.append(f"{item.get('ioc')}: lookup error")
            elif item.get("ioc"):
                bits.append(
                    f"{item.get('ioc')}: malicious={item.get('malicious') or 0} "
                    f"suspicious={item.get('suspicious') or 0}"
                )
        vt = "; ".join(bits)
    steps = brief.get("do_next") or [
        "Confirm the event in the Wazuh dashboard.",
        "Close with an analyst outcome. That records status only.",
        "Suppress the rule if this actor keeps repeating.",
    ]
    step_lines = "\n".join(f"{i}. {step}" for i, step in enumerate(steps[:3], start=1))
    meaning = (
        f"{headline} This is a {disposition} incident for {subject}, "
        f"covering {count} alert(s). {why}."
    )
    if related_ids:
        meaning += f" It shares an actor with {len(related_ids)} other case(s)."
    evidence_line = _clip(str(evidence), 200)
    vt_line = f"\nVirusTotal: {vt}" if vt else ""
    return (
        f"{MEANING_PREFIX}\n"
        "containment=not_executed\n\n"
        f"What it means\n{meaning}\n\n"
        f"Evidence\n{evidence_line}{vt_line}\n\n"
        f"Related cases\n{related_text}\n\n"
        f"Next steps\n{step_lines}"
    )


def build_investigation_prompt(
    case: dict[str, Any],
    *,
    api_url: str = "",
    packet: Optional[dict[str, Any]] = None,
) -> str:
    """Propose-only prompt. The model sees the Pop packet and must not call the LAN."""
    del api_url  # cloud VMs must not be given a lab API to call
    packet = packet if isinstance(packet, dict) else case.get("incident_packet")
    if not isinstance(packet, dict):
        packet = {
            "case_id": case.get("id"),
            "title": case.get("title"),
            "disposition": case.get("disposition"),
            "severity": case.get("severity"),
            "brief": case.get("brief") or {},
            "related_case_ids": [],
        }
    packet_text = json.dumps(packet, default=str)[:6000]
    case_id = packet.get("case_id") or case.get("id")
    return f"""You are an Agentic SOC investigation assistant for a lab environment.

## Hard rules
- **Propose only.** Never execute containment, firewall changes, process kills, or SOAR actions.
- Do **not** approve or reject. A human decides.
- Do **not** call Wazuh, private LAN APIs, or any lab HTTP API. You already have the read-only packet below.
- Use only that packet. Do not invent alerts, hosts, or enrichments that are not in it.

## Incident packet
```json
{packet_text}
```

## Deliverable
Write the complete note as your final reply. The lab host copies that reply onto incident #{case_id}. Cover:
1. What this incident means (noise vs suspicious), citing the brief
2. Evidence from the packet only
3. Related case ids from the packet
4. The three next steps for a human, and that containment stays manual
"""


def extract_result_text(result: Any) -> str:
    """Pull assistant text from an SDK RunResult (or similar namespace)."""
    if result is None:
        return ""
    if isinstance(result, str):
        return result.strip()
    for attr in ("result", "text", "output"):
        val = getattr(result, attr, None)
        if callable(val):
            continue
        if val:
            return str(val).strip()
    return str(result).strip() if result else ""


def format_investigation_note(text: str, outcome: dict[str, Any]) -> str:
    body = (text or "").strip() or "(cloud agent finished with an empty reply)"
    if len(body) > MAX_NOTE_CHARS:
        body = body[: MAX_NOTE_CHARS - 1] + "…"
    return (
        f"{NOTE_PREFIX}\n"
        f"status={outcome.get('status') or 'unknown'}\n"
        f"run_id={outcome.get('run_id') or '—'}\n"
        f"agent_id={outcome.get('agent_id') or '—'}\n"
        f"containment=not_executed\n\n"
        f"{body}"
    )


def persist_investigation_note(
    case_id: Any,
    text: str,
    *,
    outcome: dict[str, Any],
    settings: Optional[Settings] = None,
) -> dict[str, Any]:
    """Append the cloud agent's final reply onto the local case (Pop SQLite)."""
    if case_id is None or case_id == "":
        return {"ok": False, "error": "no case_id"}
    try:
        cid = int(case_id)
    except (TypeError, ValueError):
        return {"ok": False, "error": f"invalid case_id={case_id!r}"}

    from agentic_soc.tools import SocTools

    note = format_investigation_note(text, outcome)
    tools = SocTools(settings=settings)
    updated = tools.update_case(cid, note=note, author=INVESTIGATION_AUTHOR)
    if updated.get("error"):
        return {"ok": False, "error": updated.get("error"), "case_id": cid}
    LOG.info(
        "persisted cursor investigation note case=%s chars=%s run_id=%s",
        cid,
        len(note),
        outcome.get("run_id"),
    )
    return {"ok": True, "case_id": cid, "note_chars": len(note)}


def persist_meaning_note(
    case_id: Any,
    packet: dict[str, Any],
    *,
    settings: Optional[Settings] = None,
) -> dict[str, Any]:
    """Write the deterministic incident explanation. No containment."""
    if case_id is None or case_id == "":
        return {"ok": False, "error": "no case_id"}
    try:
        cid = int(case_id)
    except (TypeError, ValueError):
        return {"ok": False, "error": f"invalid case_id={case_id!r}"}
    from agentic_soc.tools import SocTools

    note = render_meaning_note(packet)
    tools = SocTools(settings=settings)
    updated = tools.update_case(cid, note=note, author=MEANING_AUTHOR)
    if updated.get("error"):
        return {"ok": False, "error": updated.get("error"), "case_id": cid}
    return {"ok": True, "case_id": cid, "note_chars": len(note), "author": MEANING_AUTHOR}


async def explain_incident(
    tools: Any,
    case: dict[str, Any],
    *,
    settings: Optional[Settings] = None,
    alert_id: Optional[str] = None,
    agent_name: Optional[str] = None,
    enrichments: Optional[list[dict[str, Any]]] = None,
    cursor_enabled: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Gather the packet, write a meaning note, optionally kick cloud from that packet."""
    settings = settings or get_settings()
    case_id = case.get("id")
    packet = await build_incident_packet(
        tools,
        case_id=int(case_id),
        alert_id=alert_id or case.get("alert_id"),
        agent_name=agent_name or case.get("agent_name"),
        enrichments=enrichments if enrichments is not None else case.get("enrichments"),
    )
    persisted = persist_meaning_note(case_id, packet, settings=settings)
    cloud_case = dict(case)
    cloud_case["incident_packet"] = packet
    from agentic_soc.connectors import configured_llm

    provider = configured_llm(settings)
    if provider is None and (cursor_enabled or dry_run):
        provider = "cursor"
    cursor: dict[str, Any] = {"skipped": True, "reason": "disabled", "provider": provider or ""}
    if provider == "cursor":
        cursor = maybe_kick_after_case_open(
            cloud_case,
            settings=settings,
            enabled=True if cursor_enabled or dry_run or provider == "cursor" else None,
            dry_run=dry_run,
        )
        cursor["provider"] = "cursor"
    elif provider == "openai":
        cursor = await _explain_with_openai(case_id, packet, settings)
    return {
        "ok": bool(persisted.get("ok")),
        "case_id": case_id,
        "packet": packet,
        "meaning_note": persisted,
        "cursor": cursor,
        "llm": cursor,
    }


async def _explain_with_openai(
    case_id: Any,
    packet: dict[str, Any],
    settings: Settings,
) -> dict[str, Any]:
    """Send the packet to the OpenAI-compatible connector and copy the reply."""
    from agentic_soc.openai_llm import draft_meaning_note, persist_openai_note

    drafted = await draft_meaning_note(settings, packet)
    drafted["provider"] = "openai"
    if not drafted.get("ok"):
        return drafted
    saved = persist_openai_note(case_id, drafted.get("note") or "", settings=settings)
    if not saved.get("ok"):
        return {"ok": False, "provider": "openai", "error": saved.get("error"), "note": drafted.get("note")}
    return {
        "ok": True,
        "provider": "openai",
        "skipped": False,
        "note": drafted.get("note"),
        "model": drafted.get("model"),
        "persisted": saved,
    }


def _notify_investigation_ready(
    case: dict[str, Any],
    note: str,
    outcome: dict[str, Any],
    settings: Settings,
) -> None:
    try:
        from agentic_soc.discord_notify import DiscordNotifier

        notifier = DiscordNotifier(settings)
        if not notifier.configured:
            return
        asyncio.run(
            notifier.notify_investigation_ready(case, note=note, outcome=outcome)
        )
    except Exception as exc:  # noqa: BLE001
        LOG.warning("discord investigation notify failed: %s", exc)


def _resolve_config(settings: Optional[Settings] = None) -> dict[str, Any]:
    settings = settings or get_settings()
    return {
        "api_key": (settings.cursor_api_key or os.environ.get("CURSOR_API_KEY") or "").strip(),
        "model": (settings.cursor_agent_model or DEFAULT_MODEL).strip() or DEFAULT_MODEL,
        "repo_url": (settings.cursor_agent_repo or "").strip(),
        "starting_ref": (
            settings.cursor_agent_starting_ref or DEFAULT_STARTING_REF
        ).strip()
        or DEFAULT_STARTING_REF,
        "api_url": (settings.agentic_soc_api_url or "").strip(),
        "cloud_pool": (settings.cursor_cloud_pool or "").strip(),
        "norepo_fallback": bool(settings.cursor_agent_norepo_fallback),
    }


def _is_scm_access_error(message: str) -> bool:
    text = (message or "").lower()
    needles = (
        "scm integration does not have access",
        "does not have access to repository",
        "error_github_app_no_access",
        "repo_not_accessible",
        "cannot access repository",
    )
    return any(n in text for n in needles)


def _run_cloud_prompt(prompt: str, cfg: dict[str, Any]) -> dict[str, Any]:
    """Blocking SDK call. Import is deferred so base installs stay light."""
    try:
        from cursor_sdk import (  # type: ignore[import-not-found]
            Agent,
            AgentOptions,
            CloudAgentOptions,
            CloudRepository,
            CursorAgentError,
        )
    except ImportError as exc:
        return {
            "ok": False,
            "error": f"cursor-sdk not installed ({exc}); pip install -e '.[cursor]'",
        }

    cloud_kwargs: dict[str, Any] = {
        "auto_create_pr": False,
        "skip_reviewer_request": True,
    }
    repo_url = cfg.get("repo_url") or ""
    if repo_url:
        cloud_kwargs["repos"] = [
            CloudRepository(url=repo_url, starting_ref=cfg.get("starting_ref") or DEFAULT_STARTING_REF)
        ]
    else:
        # No-repo cloud agent (must be enabled on the account). Still propose-only.
        cloud_kwargs["repos"] = []
        LOG.warning(
            "CURSOR_AGENT_REPO empty — launching no-repo cloud agent (account must allow it)"
        )

    pool = cfg.get("cloud_pool") or ""
    if pool:
        # Self-hosted pool name; mapping form accepted by SDK CloudAgentOptions.env
        cloud_kwargs["env"] = {"type": "pool", "name": pool}

    # Pass AGENTIC_SOC_API_URL into the VM when set (self-hosted / tunnel scenarios).
    env_vars: dict[str, str] = {}
    api_url = cfg.get("api_url") or ""
    if api_url:
        env_vars["AGENTIC_SOC_API_URL"] = api_url
    if env_vars:
        cloud_kwargs["env_vars"] = env_vars

    def _prompt(kwargs: dict[str, Any]) -> Any:
        return Agent.prompt(
            prompt,
            AgentOptions(
                api_key=cfg["api_key"],
                model=cfg["model"],
                cloud=CloudAgentOptions(**kwargs),
            ),
        )

    try:
        result = _prompt(cloud_kwargs)
    except CursorAgentError as err:
        msg = str(getattr(err, "message", "") or err)
        if (
            cfg.get("norepo_fallback")
            and repo_url
            and _is_scm_access_error(msg)
        ):
            LOG.warning(
                "GitHub/SCM cannot access %s — retrying no-repo cloud agent. "
                "Grant the Cursor GitHub App access to that repo to clone playbooks.",
                repo_url,
            )
            fallback = dict(cloud_kwargs)
            fallback["repos"] = []
            try:
                result = _prompt(fallback)
            except CursorAgentError as err2:
                return {
                    "ok": False,
                    "error": getattr(err2, "message", str(err2)),
                    "retryable": bool(getattr(err2, "is_retryable", False)),
                    "kind": "startup",
                    "scm_fallback": True,
                }
        else:
            return {
                "ok": False,
                "error": getattr(err, "message", str(err)),
                "retryable": bool(getattr(err, "is_retryable", False)),
                "kind": "startup",
            }
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc), "kind": "unexpected"}

    status = getattr(result, "status", None)
    run_id = getattr(result, "id", None)
    agent_id = getattr(result, "agent_id", None)
    if status == "error":
        return {
            "ok": False,
            "error": "run finished with status=error",
            "kind": "run",
            "run_id": run_id,
            "agent_id": agent_id,
            "status": status,
            "result_text": extract_result_text(result),
        }
    text = extract_result_text(result)
    return {
        "ok": True,
        "status": status,
        "run_id": run_id,
        "agent_id": agent_id,
        "result_text": text,
        "result_preview": text[:500],
    }


def kick_cursor_investigation(
    case: dict[str, Any],
    *,
    settings: Optional[Settings] = None,
    dry_run: bool = False,
    wait: bool = False,
) -> dict[str, Any]:
    """Start a propose-only cloud investigation for an opened case.

    By default runs in a daemon thread (fire-and-forget) so ``autonomy_loop``
    is not blocked. Set ``wait=True`` for tests / one-shot scripts.
    Set ``dry_run=True`` to only build and return the prompt (no SDK call).
    """
    settings = settings or get_settings()
    cfg = _resolve_config(settings)
    packet = case.get("incident_packet") if isinstance(case.get("incident_packet"), dict) else None
    prompt = build_investigation_prompt(case, packet=packet)

    if dry_run:
        return {
            "ok": True,
            "dry_run": True,
            "prompt": prompt,
            "model": cfg["model"],
            "repo_url": cfg["repo_url"] or None,
            "api_url": cfg["api_url"] or None,
        }

    if not cfg["api_key"]:
        return {"ok": False, "error": "CURSOR_API_KEY not set"}

    case_id = case.get("id")
    outcome_box: dict[str, Any] = {}

    def _worker() -> None:
        LOG.info(
            "cursor cloud investigation starting case=%s model=%s repo=%s",
            case_id,
            cfg["model"],
            cfg["repo_url"] or "(no-repo)",
        )
        outcome = _run_cloud_prompt(prompt, cfg)
        outcome_box.update(outcome)
        if outcome.get("ok"):
            LOG.info(
                "cursor cloud investigation finished case=%s run_id=%s agent_id=%s status=%s",
                case_id,
                outcome.get("run_id"),
                outcome.get("agent_id"),
                outcome.get("status"),
            )
            try:
                persisted = persist_investigation_note(
                    case_id,
                    outcome.get("result_text") or "",
                    outcome=outcome,
                    settings=settings,
                )
                outcome_box["persisted"] = persisted.get("ok")
                if not persisted.get("ok"):
                    LOG.warning(
                        "cursor note persist failed case=%s: %s",
                        case_id,
                        persisted.get("error"),
                    )
                else:
                    _notify_investigation_ready(
                        case,
                        format_investigation_note(
                            outcome.get("result_text") or "", outcome
                        ),
                        outcome,
                        settings,
                    )
            except Exception as exc:  # noqa: BLE001
                LOG.warning("cursor note persist error case=%s: %s", case_id, exc)
                outcome_box["persisted"] = False
        else:
            LOG.warning(
                "cursor cloud investigation failed case=%s: %s",
                case_id,
                outcome.get("error"),
            )

    if wait:
        _worker()
        return {
            "ok": bool(outcome_box.get("ok")),
            "started": True,
            "waited": True,
            "case_id": case_id,
            **{k: v for k, v in outcome_box.items() if k != "ok"},
            "error": outcome_box.get("error"),
        }

    thread = threading.Thread(
        target=_worker,
        name=f"cursor-agent-case-{case_id}",
        daemon=True,
    )
    thread.start()
    return {"ok": True, "started": True, "waited": False, "case_id": case_id, "thread": thread.name}


def maybe_kick_after_case_open(
    case: dict[str, Any],
    *,
    settings: Optional[Settings] = None,
    enabled: Optional[bool] = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Best-effort hook for autonomy_loop. Never raises."""
    try:
        settings = settings or get_settings()
        if enabled is None:
            enabled = cursor_agent_enabled(settings)
        if not enabled and not dry_run:
            return {"ok": True, "skipped": True, "reason": "disabled"}
        return kick_cursor_investigation(
            case,
            settings=settings,
            dry_run=dry_run,
            wait=False,
        )
    except Exception as exc:  # noqa: BLE001
        LOG.warning("cursor agent hook error (ignored): %s", exc)
        return {"ok": False, "error": str(exc)}
