"""Optional Cursor cloud investigation hook (propose-only, Mac-offline path).

Triggered from Pop!_OS ``autonomy_loop`` after a case is opened. Uses the
Cursor Python SDK (``cursor-sdk``) cloud runtime — not Automations, not local
Hydra. Failures are logged and never raise into the autonomy cycle.
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
from typing import Any, Optional

from agentic_soc.config import Settings, get_settings

LOG = logging.getLogger("agentic_soc.cursor_agent")

DEFAULT_MODEL = "composer-2.5"
DEFAULT_STARTING_REF = "main"
INVESTIGATION_AUTHOR = "cursor_cloud_agent"
NOTE_PREFIX = "[cursor_investigation]"
MAX_NOTE_CHARS = 50000


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


def build_investigation_prompt(
    case: dict[str, Any],
    *,
    api_url: str = "",
) -> str:
    """Build a propose-only investigation prompt from an opened-case payload."""
    case_id = case.get("id")
    reasons = case.get("reasons") or []
    if isinstance(reasons, list):
        reasons_text = "; ".join(str(r) for r in reasons if r) or "none"
    else:
        reasons_text = str(reasons)

    iocs = case.get("iocs") or []
    if isinstance(iocs, list) and iocs:
        ioc_bits = []
        for item in iocs[:8]:
            if isinstance(item, dict):
                ioc_bits.append(f"{item.get('ioc_type', 'ioc')}:{item.get('ioc')}")
            else:
                ioc_bits.append(str(item))
        iocs_text = ", ".join(ioc_bits)
    else:
        src = case.get("source_ip")
        iocs_text = f"source_ip:{src}" if src else "none"

    enrichments = case.get("enrichments") or []
    if isinstance(enrichments, list) and enrichments:
        vt_bits = []
        for e in enrichments[:6]:
            if not isinstance(e, dict):
                continue
            if e.get("error"):
                vt_bits.append(f"{e.get('ioc')}: error={e.get('error')}")
            else:
                vt_bits.append(
                    f"{e.get('ioc')}: mal={e.get('malicious')} sus={e.get('suspicious')}"
                )
        vt_text = "; ".join(vt_bits) if vt_bits else "none"
    else:
        vt_text = "none"

    api_url = (api_url or "").rstrip("/")
    extra_http = ""
    if api_url:
        extra_http = f"""
Optional extra (only if this VM can reach it): PATCH
`{api_url}/tools/update_case/{case_id}` with author `cursor_cloud_agent`.
Do **not** call approve/reject. Skip this if the URL is on a private LAN.
"""

    writeback = f"""
## Write findings back
The lab host that launched this agent copies your **final reply** onto the
case automatically. Write the complete investigation note as that final
message. Do **not** try to reach `192.168.50.254` or hang on LAN APIs.
Do **not** approve/reject or execute containment.
{extra_http}
"""

    return f"""You are an Agentic SOC investigation assistant for a lab environment.

## Hard rules
- **Propose only.** Never execute containment, firewall changes, process kills, or SOAR actions.
- Never call approve/reject endpoints; a human decides.
- Use this repo's docs and playbooks (especially `docs/SETUP_GUIDE.md`, triage heuristics, eval fixtures) to enrich judgment.
- Public Cursor cloud VMs **cannot** reach private LAN Wazuh at `192.168.50.254` unless a tunnel or self-hosted pool is configured. Prefer case payload + repo context; do not hang on unreachable LAN APIs.

## Case under investigation
- case_id: {case_id}
- title: {case.get("title") or "—"}
- disposition: {case.get("disposition") or "—"}
- severity: {case.get("severity") or "—"}
- confidence: {case.get("confidence") or "—"}
- alert_id: {case.get("alert_id") or "—"}
- agent: {case.get("agent_name") or "—"}
- rule_id / level: {case.get("rule_id") or "—"} / {case.get("rule_level") if case.get("rule_level") is not None else "—"}
- timestamp: {case.get("timestamp") or "—"}
- recommended_action: {case.get("recommended_action") or "investigate_and_document"}
- reasons: {reasons_text}
- IOCs: {iocs_text}
- VirusTotal: {vt_text}
- description: {case.get("description") or "—"}
- full_log / snippet: {(case.get("full_log") or case.get("log_snippet") or "—")[:2000]}

## Deliverable
Produce a concise investigation note covering:
1. What likely happened (lab noise vs suspicious)
2. Evidence from the payload + repo playbooks
3. Recommended next steps for a human analyst
4. Explicit reminder that containment must stay manual
{writeback}
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
    prompt = build_investigation_prompt(case, api_url=cfg["api_url"])

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
