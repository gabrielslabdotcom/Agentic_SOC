"""HITL-gated host isolation via Wazuh Active Response (Phase F).

Default is dry-run: record the plan on the case. Never called from
autonomy_loop. Execute requires HOST_ISOLATION_ENABLED=true plus an
explicit human confirm. The SIEM agent (pop-os-native) cannot be isolated.
"""

from __future__ import annotations

import json
import os
from typing import Any, Optional

PROTECTED_AGENTS = frozenset({"pop-os-native"})


def isolation_enabled() -> bool:
    return os.environ.get("HOST_ISOLATION_ENABLED", "false").lower() in ("1", "true", "yes")


def protected_agents() -> set[str]:
    raw = os.environ.get("ISOLATION_PROTECT_AGENTS") or ""
    extra = {p.strip().lower() for p in raw.split(",") if p.strip()}
    return {name.lower() for name in PROTECTED_AGENTS} | extra


def is_windows_os(os_name: Optional[str], platform: Optional[str] = None) -> bool:
    blob = f"{os_name or ''} {platform or ''}".lower()
    return "windows" in blob


def ar_command(action: str, os_name: Optional[str], platform: Optional[str] = None) -> str:
    """Command name registered in the manager ossec.conf for this OS."""
    windows = is_windows_os(os_name, platform)
    # Wazuh publishes these in etc/shared/ar.conf with a 0 suffix. The API
    # accepts that name, not the <command><name> value.
    if action == "deisolate":
        if windows:
            return os.environ.get("WAZUH_AR_DEISOLATE_CMD_WIN", "network-deisolation-win0")
        return os.environ.get("WAZUH_AR_DEISOLATE_CMD", "network-deisolation0")
    if windows:
        return os.environ.get("WAZUH_AR_ISOLATE_CMD_WIN", "network-isolation-win0")
    return os.environ.get("WAZUH_AR_ISOLATE_CMD", "network-isolation0")


def plan_host_isolation(
    agent_name: Optional[str],
    *,
    case_id: Optional[int] = None,
    action: str = "isolate",
    agent: Optional[dict[str, Any]] = None,
    lookup_error: Optional[str] = None,
    lookup_detail: Optional[str] = None,
) -> dict[str, Any]:
    """Build an isolate or de-isolate plan. Does not call Wazuh."""
    act = "deisolate_host" if action == "deisolate" else "isolate_host"
    name = (agent_name or "").strip()
    plan: dict[str, Any] = {
        "ok": False,
        "allowed": False,
        "action": act,
        "agent_name": name or None,
        "wazuh_agent_id": None,
        "agent_status": None,
        "os": None,
        "command": None,
        "reason": "plan_ready",
        "dry_run": True,
        "executed": False,
        "isolation_enabled": isolation_enabled(),
        "case_id": case_id,
    }
    if action not in ("isolate", "deisolate"):
        plan["reason"] = "invalid_action"
        return plan
    if not name:
        plan["reason"] = "no_agent_name"
        return plan
    if name.lower() in protected_agents():
        plan["reason"] = "protected_agent"
        return plan
    if lookup_error:
        plan["reason"] = lookup_error
        if lookup_detail:
            plan["error"] = lookup_detail[:500]
        return plan
    if not agent:
        plan["reason"] = "agent_not_found"
        return plan

    agent_id = str(agent.get("id") or "").strip()
    status = str(agent.get("status") or "").strip().lower()
    os_name = agent.get("os")
    platform = agent.get("platform")
    plan["wazuh_agent_id"] = agent_id or None
    plan["agent_status"] = status or None
    plan["os"] = os_name
    plan["command"] = ar_command(action, str(os_name) if os_name else None, str(platform) if platform else None)
    if not agent_id:
        plan["reason"] = "agent_not_found"
        return plan
    if status != "active":
        plan["reason"] = "agent_not_active"
        return plan
    plan["ok"] = True
    plan["allowed"] = True
    plan["reason"] = "plan_ready"
    return plan


def _affected_ids(api: dict[str, Any]) -> list[str]:
    data = api.get("data") if isinstance(api.get("data"), dict) else {}
    items = data.get("affected_items") or []
    return [str(item) for item in items]


def _failed_items(api: dict[str, Any]) -> list[Any]:
    data = api.get("data") if isinstance(api.get("data"), dict) else {}
    failed = data.get("failed_items") or []
    return list(failed) if isinstance(failed, list) else [failed]


async def execute_host_isolation(
    client: Any,
    plan: dict[str, Any],
    *,
    confirm: bool = False,
) -> dict[str, Any]:
    """Send the planned active-response command. Never auto."""
    result = dict(plan)
    result["executed"] = False
    if not result.get("allowed"):
        return result
    if not confirm:
        result["reason"] = "confirm_required"
        return result
    if not isolation_enabled():
        result["reason"] = "isolation_disabled"
        return result

    agent_id = str(result.get("wazuh_agent_id") or "").strip()
    command = str(result.get("command") or "").strip()
    if not agent_id or not command:
        result["ok"] = False
        result["reason"] = "plan_incomplete"
        return result
    try:
        api = await client.active_response([agent_id], command)
    except Exception as exc:
        result["ok"] = False
        result["reason"] = "execute_failed"
        result["error"] = str(exc)[:500]
        return result

    result["dry_run"] = False
    failed = _failed_items(api if isinstance(api, dict) else {})
    affected = _affected_ids(api if isinstance(api, dict) else {})
    error_code = api.get("error") if isinstance(api, dict) else None
    result["api"] = {
        "error": error_code,
        "affected_items": affected,
        "failed_items": failed[:5],
    }
    accepted = agent_id in affected and not failed and error_code in (0, None)
    if not accepted:
        result["ok"] = False
        result["reason"] = "wazuh_rejected"
        detail = ""
        if failed:
            detail = str(failed[0])[:500]
        elif isinstance(api, dict) and api.get("message"):
            detail = str(api.get("message"))[:500]
        if detail:
            result["error"] = detail
        return result
    result["ok"] = True
    result["executed"] = True
    result["reason"] = "active_response_sent"
    return result


def plan_note(plan: dict[str, Any], *, tag: str = "isolation_plan") -> str:
    body = {k: v for k, v in plan.items() if k != "argv"}
    return f"[{tag}]\n" + json.dumps(body, indent=2)
