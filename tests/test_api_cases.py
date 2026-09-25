"""API tests for case get / approve endpoints (lab-safe, no containment)."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentic_soc import api as api_mod
from agentic_soc.config import Settings
from agentic_soc.policy import ANALYST
from agentic_soc.tools import SocTools


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    db = tmp_path / "cases.sqlite"
    settings = Settings(cases_db_path=str(db), wazuh_dashboard_url="https://example.test")
    tools = SocTools(settings=settings, role=ANALYST)
    monkeypatch.setattr(api_mod, "get_tools", lambda: tools)
    return TestClient(api_mod.app)


def test_get_case_and_approve(client: TestClient) -> None:
    opened = client.post(
        "/tools/open_case",
        json={
            "title": "Lab port scan",
            "alert_id": "abc-123",
            "agent_name": "pop-os-native",
            "summary": "Aggregate UFW blocks",
            "severity": "high",
            "recommended_action": "document only",
        },
    )
    assert opened.status_code == 200
    case_id = opened.json()["id"]

    got = client.get(f"/tools/get_case/{case_id}")
    assert got.status_code == 200
    body = got.json()
    assert body["title"] == "Lab port scan"
    assert body["status"] == "open"
    assert body["recommended_action"] == "document only"

    missing = client.get("/tools/get_case/99999")
    assert missing.status_code == 404

    approved = client.post(
        f"/tools/approve_case/{case_id}",
        json={"approved": True, "note": "confirmed lab scan", "author": "pytest"},
    )
    assert approved.status_code == 200
    result = approved.json()
    assert result["status"] == "confirmed_compromise"
    assert result["analyst_disposition"] == "confirmed_compromise"
    notes = " ".join(n["note"] for n in result.get("notes") or [])
    assert "CONFIRMED_COMPROMISE" in notes
    assert "containment=not_executed" in notes
    assert "confirmed lab scan" in notes


def test_reject_case(client: TestClient) -> None:
    opened = client.post(
        "/tools/open_case",
        json={"title": "Noise", "summary": "CIS", "recommended_action": "ignore"},
    )
    case_id = opened.json()["id"]

    rejected = client.post(
        f"/tools/approve_case/{case_id}",
        json={"approved": False, "note": "duplicate noise"},
    )
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "false_positive"

    listed = client.get("/tools/list_cases?status=false_positive")
    assert listed.status_code == 200
    ids = [c["id"] for c in listed.json()["cases"]]
    assert case_id in ids


def test_pending_filter_maps_to_open(client: TestClient) -> None:
    client.post("/tools/open_case", json={"title": "Pending queue"})
    pending = client.get("/tools/list_cases?status=pending")
    assert pending.status_code == 200
    assert pending.json()["count"] >= 1
    assert all(c["status"] == "open" for c in pending.json()["cases"])


def test_ui_config_and_dashboard(client: TestClient) -> None:
    cfg = client.get("/tools/ui_config")
    assert cfg.status_code == 200
    data = cfg.json()
    assert data["app_name"] == "Agentic SOC Analyst"
    assert data["wazuh_dashboard_url"] == "https://example.test"
    assert data["containment_enabled"] is False
    assert data["instance"] in ("mac-local", "pop-live")
    assert "banner" in data
    assert data["lab_mode"] is True

    dash = client.get("/dashboard/", follow_redirects=True)
    assert dash.status_code == 200
    assert "Agentic SOC Analyst" in dash.text
    assert "instance-banner" in dash.text
    assert "min-level 8" in dash.text
    assert "Cursor investigation" in dash.text
    assert "rule_id" in dash.text
    assert "auto-close" in dash.text
    assert "Select all" in dash.text
    assert "Apply to selected" in dash.text
    assert "False Positive" in dash.text
    assert "Confirmed Compromise" in dash.text
    assert "Containment plan" in dash.text


def test_approve_records_feedback(client: TestClient) -> None:
    opened = client.post(
        "/tools/open_case",
        json={
            "title": "SSH auth",
            "alert_id": "auth-1",
            "rule_id": "5710",
            "source_ip": "203.0.113.80",
            "recommended_action": "investigate_and_document",
        },
    )
    case_id = opened.json()["id"]
    rejected = client.post(
        f"/tools/approve_case/{case_id}",
        json={"approved": False, "note": "known lab hydra", "author": "pytest"},
    )
    assert rejected.status_code == 200
    summary = client.get("/tools/feedback_summary")
    assert summary.status_code == 200
    body = summary.json()
    assert body["rejected"] >= 1
    assert any(
        item["case_id"] == case_id and item["approved"] is False
        for item in body["items"]
    )


def test_bulk_approve_open_cases_only(client: TestClient) -> None:
    a = client.post("/tools/open_case", json={"title": "scan a"}).json()["id"]
    b = client.post("/tools/open_case", json={"title": "scan b"}).json()["id"]
    done = client.post("/tools/open_case", json={"title": "already decided"}).json()["id"]
    client.post(f"/tools/approve_case/{done}", json={"approved": True, "note": "solo"})

    bulk = client.post(
        "/tools/approve_cases",
        json={
            "case_ids": [a, b, done],
            "approved": False,
            "note": "lab nmap burst",
            "author": "pytest",
        },
    )
    assert bulk.status_code == 200
    body = bulk.json()
    assert body["containment_executed"] is False
    assert body["count"] == 2
    assert {row["id"] for row in body["updated"]} == {a, b}
    assert all(row["status"] == "false_positive" for row in body["updated"])
    skipped_ids = {row["id"] for row in body["skipped"]}
    assert done in skipped_ids
    assert client.get(f"/tools/get_case/{a}").json()["status"] == "false_positive"
    assert client.get(f"/tools/get_case/{done}").json()["status"] == "confirmed_compromise"


def test_containment_plan_and_disabled_execute(client: TestClient) -> None:
    opened = client.post(
        "/tools/open_case",
        json={
            "title": "scan",
            "source_ip": "203.0.113.80",
            "recommended_action": "investigate_and_document",
        },
    )
    case_id = opened.json()["id"]
    plan = client.get(f"/tools/containment_plan?case_id={case_id}&record=true")
    assert plan.status_code == 200
    body = plan.json()
    assert body["allowed"] is True
    assert body["dry_run"] is True
    assert "ufw" in (body.get("command") or "")

    blocked = client.get("/tools/containment_plan?source_ip=192.168.50.254")
    assert blocked.status_code == 200
    assert blocked.json()["allowed"] is False

    exe = client.post(
        "/tools/execute_containment",
        json={"case_id": case_id, "confirm": True, "author": "pytest"},
    )
    assert exe.status_code == 200
    assert exe.json()["executed"] is False
    assert exe.json()["reason"] == "containment_disabled"


def test_isolation_plan_and_execute_disabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HOST_ISOLATION_ENABLED", raising=False)
    db = tmp_path / "cases.sqlite"
    settings = Settings(cases_db_path=str(db), wazuh_dashboard_url="https://example.test")
    tools = SocTools(settings=settings, role=ANALYST)

    async def _resolve(name: str) -> dict:
        return {
            "ok": True,
            "agent": {
                "id": "005",
                "name": name,
                "status": "active",
                "os": "Microsoft Windows 10",
                "platform": "windows",
                "ip": "203.0.113.7",
            },
        }

    tools.wazuh.resolve_agent_by_name = _resolve  # type: ignore[method-assign]
    monkeypatch.setattr(api_mod, "get_tools", lambda: tools)
    client = TestClient(api_mod.app)

    opened = client.post(
        "/tools/open_case",
        json={"title": "endpoint", "alert_id": "iso-api", "agent_name": "win10"},
    )
    assert opened.status_code == 200
    case_id = opened.json()["id"]
    plan = client.get(f"/tools/isolation_plan?case_id={case_id}&record=true")
    assert plan.status_code == 200
    body = plan.json()
    assert body["allowed"] is True
    assert body["dry_run"] is True
    assert body["command"] == "network-isolation-win0"
    assert body["recorded"] is True

    protected = client.get("/tools/isolation_plan?agent_name=pop-os-native")
    assert protected.status_code == 200
    assert protected.json()["allowed"] is False
    assert protected.json()["reason"] == "protected_agent"

    exe = client.post(
        "/tools/execute_isolation",
        json={"case_id": case_id, "confirm": True, "author": "pytest"},
    )
    assert exe.status_code == 200
    assert exe.json()["executed"] is False
    assert exe.json()["reason"] == "isolation_disabled"

    missing = client.get("/tools/isolation_plan")
    assert missing.status_code == 400


def test_ui_config_pop_live_banner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db = tmp_path / "cases.sqlite"
    settings = Settings(
        cases_db_path=str(db),
        wazuh_dashboard_url="https://example.test",
        agentic_soc_instance="pop-live",
    )
    tools = SocTools(settings=settings, role=ANALYST)
    monkeypatch.setattr(api_mod, "get_tools", lambda: tools)
    client = TestClient(api_mod.app)
    data = client.get("/tools/ui_config").json()
    assert data["instance"] == "pop-live"
    assert "LIVE Pop" in data["banner"]
    assert data["containment_enabled"] is False
    assert data["host_isolation_enabled"] is False
    assert "OR" in data["note"] or "auth" in data["note"].lower()
    assert "HOST_ISOLATION_ENABLED" in data["note"]


def test_disposition_endpoint_and_unknown(client: TestClient) -> None:
    opened = client.post("/tools/open_case", json={"title": "lab nmap"}).json()["id"]
    ok = client.post(
        f"/tools/approve_case/{opened}",
        json={"disposition": "benign", "note": "generate_portscan_lab.py"},
    )
    assert ok.status_code == 200
    assert ok.json()["status"] == "benign"
    assert ok.json()["analyst_disposition"] == "benign"

    bad = client.post(
        "/tools/open_case",
        json={"title": "other"},
    ).json()["id"]
    unknown = client.post(
        f"/tools/approve_case/{bad}",
        json={"disposition": "not_a_real_outcome"},
    )
    assert unknown.status_code == 422
