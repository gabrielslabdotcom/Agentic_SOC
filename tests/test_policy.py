"""Role policy: investigator proposes, analyst approves, nobody auto-executes."""

from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi.testclient import TestClient

from agentic_soc import api as api_mod
from agentic_soc.config import Settings
from agentic_soc.policy import ANALYST, INVESTIGATOR, READER, allow
from agentic_soc.tools import SocTools


def _settings(tmp_path: Path) -> Settings:
    return Settings(cases_db_path=str(tmp_path / "cases.sqlite"), wazuh_dashboard_url="https://example.test")


def test_role_ladder() -> None:
    assert allow(READER, "get_case") is True
    assert allow(READER, "open_case") is False
    assert allow(INVESTIGATOR, "open_case") is True
    assert allow(INVESTIGATOR, "approve_case") is False
    assert allow(INVESTIGATOR, "execute_containment") is False
    assert allow(ANALYST, "approve_case") is True
    assert allow(ANALYST, "execute_containment") is True
    assert allow("nope", "open_case") is False


def test_reader_cannot_open_investigator_cannot_approve_or_execute(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.delenv("HOST_ISOLATION_ENABLED", raising=False)
    settings = _settings(tmp_path)
    reader = SocTools(settings=settings, role=READER)
    denied_open = reader.open_case(title="nope", alert_id="r1")
    assert denied_open["error"] == "policy_denied"
    assert denied_open["role"] == READER
    assert denied_open["action"] == "open_case"

    investigator = SocTools(settings=settings, role=INVESTIGATOR)
    opened = investigator.open_case(
        title="scan",
        alert_id="i1",
        source_ip="203.0.113.40",
    )
    assert opened.get("error") != "policy_denied"
    proposed = investigator.propose_action(
        opened["id"],
        "block_source_ip",
        auto_execute=True,
    )
    note = proposed["notes"][-1]["note"]
    assert '"auto_execute": false' in note
    assert '"executed": false' in note
    assert "policy_denied" not in note

    approve = investigator.resolve_proposal(opened["id"], disposition="benign")
    assert approve["error"] == "policy_denied"
    assert approve["role"] == INVESTIGATOR
    assert approve["action"] == "approve_case"

    exe = investigator.execute_containment(opened["id"], confirm=True)
    assert exe["error"] == "policy_denied"
    assert exe["action"] == "execute_containment"
    assert exe.get("executed") is not True

    iso = asyncio.run(investigator.execute_isolation(opened["id"], confirm=True))
    assert iso["error"] == "policy_denied"
    assert iso["action"] == "execute_isolation"
    assert iso.get("executed") is not True

    analyst = SocTools(settings=settings, role=ANALYST)
    closed = analyst.resolve_proposal(opened["id"], disposition="benign", author="pytest")
    assert closed.get("error") != "policy_denied"
    assert closed["analyst_disposition"] == "benign"

    blocked = analyst.execute_containment(opened["id"], confirm=True, author="pytest")
    assert blocked.get("error") != "policy_denied"
    assert blocked["executed"] is False
    assert blocked["reason"] == "containment_disabled"

    async def _resolve(name: str) -> dict:
        return {
            "ok": True,
            "agent": {
                "id": "009",
                "name": name,
                "status": "active",
                "os": "Ubuntu",
                "platform": "ubuntu",
                "ip": "203.0.113.9",
            },
        }

    analyst.wazuh.resolve_agent_by_name = _resolve  # type: ignore[method-assign]
    host = analyst.open_case(title="endpoint", alert_id="iso-policy", agent_name="lab-linux")
    iso_blocked = asyncio.run(analyst.execute_isolation(host["id"], confirm=True, author="pytest"))
    assert iso_blocked.get("error") != "policy_denied"
    assert iso_blocked["executed"] is False
    assert iso_blocked["reason"] == "isolation_disabled"


def test_api_investigator_approve_is_forbidden(tmp_path: Path, monkeypatch) -> None:
    settings = _settings(tmp_path)
    tools = SocTools(settings=settings, role=INVESTIGATOR)
    opened = tools.open_case(title="scan", alert_id="api-i", source_ip="203.0.113.41")
    monkeypatch.setattr(api_mod, "get_tools", lambda: tools)
    client = TestClient(api_mod.app)
    response = client.post(
        f"/tools/approve_case/{opened['id']}",
        json={"disposition": "benign", "author": "pytest"},
    )
    assert response.status_code == 403
    detail = response.json()["detail"]
    assert detail["error"] == "policy_denied"
    assert detail["role"] == INVESTIGATOR
