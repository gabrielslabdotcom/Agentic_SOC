"""Host isolation plan safety (dry-run unless HOST_ISOLATION_ENABLED and confirm)."""

from __future__ import annotations

import asyncio

from pathlib import Path

from agentic_soc.config import Settings
from agentic_soc.isolation import (
    execute_host_isolation,
    plan_host_isolation,
)
from agentic_soc.policy import ANALYST
from agentic_soc.tools import SocTools


_LINUX = {
    "id": "005",
    "name": "lab-linux",
    "status": "active",
    "os": "Ubuntu",
    "platform": "ubuntu",
    "ip": "203.0.113.5",
}


def test_plan_linux_active_agent() -> None:
    plan = plan_host_isolation("lab-linux", case_id=4, action="isolate", agent=_LINUX)
    assert plan["allowed"] is True
    assert plan["dry_run"] is True
    assert plan["executed"] is False
    assert plan["wazuh_agent_id"] == "005"
    assert plan["command"] == "network-isolation0"
    assert plan["reason"] == "plan_ready"


def test_plan_windows_uses_win_command() -> None:
    agent = {
        "id": "007",
        "name": "win10",
        "status": "active",
        "os": "Microsoft Windows 10",
        "platform": "windows",
    }
    plan = plan_host_isolation("win10", action="deisolate", agent=agent)
    assert plan["allowed"] is True
    assert plan["command"] == "network-deisolation-win0"
    assert plan["action"] == "deisolate_host"


def test_plan_blocks_siem_agent() -> None:
    plan = plan_host_isolation("pop-os-native", case_id=1)
    assert plan["allowed"] is False
    assert plan["reason"] == "protected_agent"
    assert plan["command"] is None


def test_plan_extra_protected_name(monkeypatch) -> None:
    monkeypatch.setenv("ISOLATION_PROTECT_AGENTS", "win-soc")
    plan = plan_host_isolation("win-soc", agent={"id": "008", "status": "active", "os": "Windows"})
    assert plan["reason"] == "protected_agent"


def test_plan_rejects_blank_and_inactive() -> None:
    blank = plan_host_isolation("  ")
    assert blank["reason"] == "no_agent_name"
    down = plan_host_isolation(
        "lab-linux",
        agent={**_LINUX, "status": "disconnected"},
    )
    assert down["allowed"] is False
    assert down["reason"] == "agent_not_active"


def test_plan_lookup_errors() -> None:
    missing = plan_host_isolation("nope", lookup_error="agent_not_found")
    assert missing["reason"] == "agent_not_found"
    ambiguous = plan_host_isolation("dup", lookup_error="agent_name_ambiguous")
    assert ambiguous["reason"] == "agent_name_ambiguous"


def test_execute_without_confirm_is_noop() -> None:
    plan = plan_host_isolation("lab-linux", case_id=3, agent=_LINUX)
    result = asyncio.run(execute_host_isolation(object(), plan, confirm=False))
    assert result["executed"] is False
    assert result["reason"] == "confirm_required"


def test_execute_disabled_by_default(monkeypatch) -> None:
    monkeypatch.delenv("HOST_ISOLATION_ENABLED", raising=False)
    plan = plan_host_isolation("lab-linux", case_id=3, agent=_LINUX)
    result = asyncio.run(execute_host_isolation(object(), plan, confirm=True))
    assert result["executed"] is False
    assert result["reason"] == "isolation_disabled"


def test_execute_when_enabled_sends_command(monkeypatch) -> None:
    monkeypatch.setenv("HOST_ISOLATION_ENABLED", "true")
    plan = plan_host_isolation("lab-linux", case_id=9, agent=_LINUX)
    seen: dict[str, object] = {}

    class _Client:
        async def active_response(self, agent_ids, command, arguments=None):
            seen["ids"] = list(agent_ids)
            seen["command"] = command
            return {"error": 0, "data": {"affected_items": list(agent_ids), "failed_items": []}}

    result = asyncio.run(execute_host_isolation(_Client(), plan, confirm=True))
    assert result["executed"] is True
    assert result["reason"] == "active_response_sent"
    assert seen["ids"] == ["005"]
    assert seen["command"] == "network-isolation0"


def test_execute_wazuh_rejection(monkeypatch) -> None:
    monkeypatch.setenv("HOST_ISOLATION_ENABLED", "true")
    plan = plan_host_isolation("lab-linux", agent=_LINUX)

    class _Client:
        async def active_response(self, agent_ids, command, arguments=None):
            return {
                "error": 1,
                "data": {"affected_items": [], "failed_items": [{"error": {"message": "missing"}}]},
            }

    result = asyncio.run(execute_host_isolation(_Client(), plan, confirm=True))
    assert result["executed"] is False
    assert result["reason"] == "wazuh_rejected"


def test_successful_execute_is_remembered_on_the_case(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HOST_ISOLATION_ENABLED", "true")
    settings = Settings(
        cases_db_path=str(tmp_path / "cases.sqlite"),
        wazuh_dashboard_url="https://example.test",
    )
    tools = SocTools(settings=settings, role=ANALYST)
    opened = tools.cases.open_case(title="host", alert_id="iso-1", agent_name="lab-linux")

    async def resolve_agent_by_name(name: str) -> dict:
        assert name == "lab-linux"
        return {"ok": True, "agent": _LINUX}

    async def active_response(agent_ids, command, arguments=None):
        return {"error": 0, "data": {"affected_items": list(agent_ids), "failed_items": []}}

    tools.wazuh.resolve_agent_by_name = resolve_agent_by_name  # type: ignore[method-assign]
    tools.wazuh.active_response = active_response  # type: ignore[method-assign]

    result = asyncio.run(
        tools.execute_isolation(opened["id"], action="isolate", confirm=True, author="pytest")
    )
    assert result["executed"] is True
    case = tools.get_case(opened["id"])
    state = case["isolation_state"]
    assert state["action"] == "isolate"
    assert state["command"] == "network-isolation0"
    assert state["wazuh_agent_id"] == "005"
    assert state["agent_name"] == "lab-linux"

    result = asyncio.run(
        tools.execute_isolation(opened["id"], action="deisolate", confirm=True, author="pytest")
    )
    assert result["executed"] is True
    state = tools.get_case(opened["id"])["isolation_state"]
    assert state["action"] == "deisolate"
    assert state["command"] == "network-deisolation0"
