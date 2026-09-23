"""Who may call which SocTools action. Not a login system.

reader < investigator < analyst. Unknown roles are treated as reader.
Execute still also requires CONTAINMENT_ENABLED inside containment.py.
"""

from __future__ import annotations

from typing import Any

READER = "reader"
INVESTIGATOR = "investigator"
ANALYST = "analyst"

_RANK = {READER: 1, INVESTIGATOR: 2, ANALYST: 3}

# Investigator: open, update, attach, propose, entity writes, noise auto-close.
_INVESTIGATOR_ACTIONS = frozenset(
    {
        "open_case",
        "update_case",
        "propose_action",
        "auto_close_noise",
        "attach_alert",
        "upsert_entity",
        "link_alert_to_entity",
        "link_case_to_entity",
        "correlate_alert",
        "record_containment_plan",
    }
)

# Analyst: close a case, manage suppressions, execute containment.
_ANALYST_ACTIONS = frozenset(
    {
        "approve_case",
        "add_suppression",
        "disable_suppression",
        "execute_containment",
    }
)


def normalize_role(role: str | None) -> str:
    cleaned = (role or "").strip().lower()
    if cleaned in _RANK:
        return cleaned
    return READER


def required_role(action: str) -> str:
    if action in _ANALYST_ACTIONS:
        return ANALYST
    if action in _INVESTIGATOR_ACTIONS:
        return INVESTIGATOR
    return READER


def allow(role: str | None, action: str) -> bool:
    return _RANK[normalize_role(role)] >= _RANK[required_role(action)]


def denial(role: str | None, action: str) -> dict[str, Any]:
    return {
        "ok": False,
        "error": "policy_denied",
        "role": normalize_role(role),
        "action": action,
    }
