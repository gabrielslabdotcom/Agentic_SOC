"""Rule suppressions + queue metrics (analyst-managed, no containment)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentic_soc import api as api_mod
from agentic_soc.cases import CaseStore
from agentic_soc.config import Settings
from agentic_soc.policy import ANALYST
from agentic_soc.tools import SocTools


@pytest.fixture()
def store(tmp_path: Path) -> CaseStore:
    return CaseStore(tmp_path / "cases.sqlite")


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    db = tmp_path / "cases.sqlite"
    settings = Settings(cases_db_path=str(db), wazuh_dashboard_url="https://example.test")
    tools = SocTools(settings=settings, role=ANALYST)
    monkeypatch.setattr(api_mod, "get_tools", lambda: tools)
    return TestClient(api_mod.app)


def test_any_source_suppression_matches_missing_ip(store: CaseStore) -> None:
    added = store.add_suppression(
        rule_id="2501",
        disposition="informational",
        note="lab auth flood",
        created_by="pytest",
    )
    assert added["id"]
    assert added["any_source"] is True

    hit = store.match_suppression(rule_id="2501", source_ip=None)
    assert hit["match"] is True
    assert hit["reason"] == "any_source"
    assert hit["disposition"] == "informational"

    miss = store.match_suppression(rule_id="5710", source_ip=None)
    assert miss["match"] is False


def test_exact_source_preferred_over_any(store: CaseStore) -> None:
    store.add_suppression(rule_id="100102", disposition="informational")
    store.add_suppression(
        rule_id="100102",
        source_ip="192.0.2.10",
        disposition="false_positive",
    )
    hit = store.match_suppression(rule_id="100102", source_ip="192.0.2.10")
    assert hit["match"] is True
    assert hit["reason"] == "exact_source"
    assert hit["disposition"] == "false_positive"

    any_hit = store.match_suppression(rule_id="100102", source_ip="198.51.100.1")
    assert any_hit["match"] is True
    assert any_hit["reason"] == "any_source"
    assert any_hit["disposition"] == "informational"


def test_confirmed_compromise_cannot_suppress(store: CaseStore) -> None:
    bad = store.add_suppression(rule_id="2501", disposition="confirmed_compromise")
    assert "error" in bad


def test_disable_and_expiry(store: CaseStore) -> None:
    row = store.add_suppression(rule_id="5503", disposition="false_positive")
    sid = int(row["id"])
    store.disable_suppression(sid)
    assert store.match_suppression(rule_id="5503")["match"] is False

    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    store.add_suppression(
        rule_id="5716",
        disposition="informational",
        expires_at=past,
    )
    assert store.match_suppression(rule_id="5716")["match"] is False


def test_suggestions_require_repeats(store: CaseStore) -> None:
    opened = store.open_case(
        title="auth",
        alert_id="a1",
        rule_id="2501",
        source_ip=None,
    )
    store.resolve_proposal(opened["id"], disposition="benign", note="lab")
    sug = store.suppression_suggestions(min_count=2)
    assert sug["count"] == 0

    opened2 = store.open_case(
        title="auth2",
        alert_id="a2",
        rule_id="2501",
    )
    store.resolve_proposal(opened2["id"], disposition="false_positive", note="again")
    sug2 = store.suppression_suggestions(min_count=2)
    assert sug2["count"] >= 1
    assert sug2["suggestions"][0]["rule_id"] == "2501"
    assert sug2["suggestions"][0]["any_source"] is True


def test_queue_metrics(store: CaseStore) -> None:
    c1 = store.open_case(title="open one", alert_id="o1")
    c2 = store.open_case(title="noise", alert_id="o2")
    store.auto_close_noise(c2["id"], note="heuristic")
    store.resolve_proposal(c1["id"], disposition="benign", note="ok")
    store.add_suppression(rule_id="2501", disposition="informational")
    m = store.queue_metrics()
    assert m["open"] == 0
    assert m["auto_closed"] == 1
    assert m["human_closed"] == 1
    assert m["human_outcomes"].get("benign") == 1
    assert m["active_suppressions"] == 1
    assert m["cases_total"] == 2


def test_api_suppressions_and_metrics(client: TestClient) -> None:
    metrics = client.get("/tools/queue_metrics")
    assert metrics.status_code == 200
    assert "open" in metrics.json()

    added = client.post(
        "/tools/add_suppression",
        json={
            "rule_id": "2501",
            "disposition": "informational",
            "note": "auth flood",
        },
    )
    assert added.status_code == 200
    body = added.json()
    assert body["rule_id"] == "2501"
    assert body["any_source"] is True

    listed = client.get("/tools/list_suppressions")
    assert listed.status_code == 200
    assert listed.json()["count"] >= 1

    matched = client.get("/tools/match_suppression?rule_id=2501")
    assert matched.status_code == 200
    assert matched.json()["match"] is True

    disabled = client.post(f"/tools/disable_suppression/{body['id']}")
    assert disabled.status_code == 200
    assert disabled.json()["active"] is False

    bad = client.post(
        "/tools/add_suppression",
        json={"rule_id": "2501", "disposition": "confirmed_compromise"},
    )
    assert bad.status_code == 400

    sug = client.get("/tools/suppression_suggestions")
    assert sug.status_code == 200
    assert "suggestions" in sug.json()
