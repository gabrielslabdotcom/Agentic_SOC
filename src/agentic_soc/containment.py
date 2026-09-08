"""HITL-gated lab containment plans (Phase E).

Default is dry-run: record the UFW deny command on the case.
Never called from autonomy_loop. Execute requires CONTAINMENT_ENABLED=true
plus an explicit human confirm. Auto-containment stays off.
"""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
from typing import Any, Optional

PROTECTED_IPS = frozenset(
    {
        "127.0.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "192.168.50.254",  # Pop Wazuh / SSH host
    }
)


def containment_enabled() -> bool:
    return os.environ.get("CONTAINMENT_ENABLED", "false").lower() in ("1", "true", "yes")


def extra_protected_ips() -> set[str]:
    raw = os.environ.get("CONTAINMENT_PROTECT_IPS") or ""
    extra = {p.strip() for p in raw.split(",") if p.strip()}
    return set(PROTECTED_IPS) | extra


def plan_block_source_ip(
    source_ip: Optional[str],
    *,
    case_id: Optional[int] = None,
) -> dict[str, Any]:
    """Build a single-IP UFW deny plan. Does not run anything."""
    ip = (source_ip or "").strip()
    if not ip:
        return {
            "ok": False,
            "allowed": False,
            "action": "block_source_ip",
            "reason": "no_source_ip",
            "command": None,
            "dry_run": True,
            "containment_enabled": containment_enabled(),
        }
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return {
            "ok": False,
            "allowed": False,
            "action": "block_source_ip",
            "source_ip": ip,
            "reason": "invalid_ip",
            "command": None,
            "dry_run": True,
            "containment_enabled": containment_enabled(),
        }
    if parsed.version != 4:
        return {
            "ok": False,
            "allowed": False,
            "action": "block_source_ip",
            "source_ip": ip,
            "reason": "ipv6_not_supported",
            "command": None,
            "dry_run": True,
            "containment_enabled": containment_enabled(),
        }
    if parsed.is_loopback or parsed.is_multicast or parsed.is_unspecified or parsed.is_link_local:
        return {
            "ok": False,
            "allowed": False,
            "action": "block_source_ip",
            "source_ip": ip,
            "reason": "protected_special_range",
            "command": None,
            "dry_run": True,
            "containment_enabled": containment_enabled(),
        }
    if ip in extra_protected_ips():
        return {
            "ok": False,
            "allowed": False,
            "action": "block_source_ip",
            "source_ip": ip,
            "reason": "protected_lab_host",
            "command": None,
            "dry_run": True,
            "containment_enabled": containment_enabled(),
        }

    comment = f"agentic-soc-case-{case_id}" if case_id is not None else "agentic-soc"
    argv = ["sudo", "-n", "ufw", "insert", "1", "deny", "from", ip, "comment", comment]
    return {
        "ok": True,
        "allowed": True,
        "action": "block_source_ip",
        "source_ip": ip,
        "reason": "plan_ready",
        "command": " ".join(argv),
        "argv": argv,
        "dry_run": True,
        "containment_enabled": containment_enabled(),
        "case_id": case_id,
    }


def execute_block_source_ip(
    source_ip: Optional[str],
    *,
    case_id: Optional[int] = None,
    confirm: bool = False,
) -> dict[str, Any]:
    """Run the planned UFW deny only when enabled + confirmed. Never auto."""
    plan = plan_block_source_ip(source_ip, case_id=case_id)
    plan["executed"] = False
    if not plan.get("allowed"):
        return plan
    if not confirm:
        plan["reason"] = "confirm_required"
        return plan
    if not containment_enabled():
        plan["reason"] = "containment_disabled"
        return plan

    argv = list(plan.get("argv") or [])
    ufw = shutil.which("ufw")
    sudo = shutil.which("sudo")
    if not ufw or not sudo:
        plan["ok"] = False
        plan["reason"] = "ufw_or_sudo_missing"
        plan["error"] = "ufw/sudo not on PATH (expected on Pop lab host)"
        return plan
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        plan["ok"] = False
        plan["reason"] = "execute_failed"
        plan["error"] = str(exc)
        return plan
    plan["dry_run"] = False
    plan["returncode"] = proc.returncode
    plan["stdout"] = (proc.stdout or "")[:2000]
    plan["stderr"] = (proc.stderr or "")[:2000]
    if proc.returncode != 0:
        plan["ok"] = False
        plan["reason"] = "ufw_nonzero"
        plan["error"] = (proc.stderr or proc.stdout or "ufw failed")[:500]
        return plan
    plan["executed"] = True
    plan["reason"] = "ufw_deny_inserted"
    return plan


def plan_note(plan: dict[str, Any]) -> str:
    body = {k: v for k, v in plan.items() if k != "argv"}
    return "[containment_plan]\n" + json.dumps(body, indent=2)
