"""API tests for case get / approve endpoints (lab-safe, no containment)."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentic_soc import api as api_mod
from agentic_soc.config import Settings
from agentic_soc.tools import SocTools


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    db = tmp_path / "cases.sqlite"
    settings = Settings(cases_db_path=str(db), wazuh_dashboard_url="https://example.test")
    tools = SocTools(settings=settings)
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
    assert result["status"] == "approved"
    notes = " ".join(n["note"] for n in result.get("notes") or [])
    assert "APPROVED" in notes
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
    assert rejected.json()["status"] == "rejected"

    listed = client.get("/tools/list_cases?status=rejected")
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


def test_ui_config_pop_live_banner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db = tmp_path / "cases.sqlite"
    settings = Settings(
        cases_db_path=str(db),
        wazuh_dashboard_url="https://example.test",
        agentic_soc_instance="pop-live",
    )
    tools = SocTools(settings=settings)
    monkeypatch.setattr(api_mod, "get_tools", lambda: tools)
    client = TestClient(api_mod.app)
    data = client.get("/tools/ui_config").json()
    assert data["instance"] == "pop-live"
    assert "LIVE Pop" in data["banner"]
    assert data["containment_enabled"] is False
