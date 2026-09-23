"""Incident attach: same actor joins; missing actor does not; severity rise pages."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentic_soc import api as api_mod
from agentic_soc.cases import CaseStore
from agentic_soc.config import Settings
from agentic_soc.tools import SocTools

import importlib.util

_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "autonomy_loop",
    _ROOT / "scripts" / "autonomy_loop.py",
)
assert _SPEC and _SPEC.loader
autonomy_loop = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(autonomy_loop)


def _open(store: CaseStore, *, alert_id: str, source_ip: str | None, user: str | None, severity: str = "medium") -> dict:
    brief = {
        "headline": "lab",
        "actors": {"source_ip": source_ip, "user": user, "agent": "lab-agent"},
        "do_next": ["a", "b", "c"],
    }
    return store.open_case(
        title="incident",
        alert_id=alert_id,
        rule_id="100102",
        source_ip=source_ip,
        severity=severity,
        brief=brief,
    )


def test_same_ip_joins_within_window(tmp_path: Path) -> None:
    store = CaseStore(tmp_path / "cases.sqlite")
    parent = _open(store, alert_id="a1", source_ip="198.51.100.10", user="bob")
    found = store.find_open_incident(source_ip="198.51.100.10", actor_user="other")
    assert found["match"] is True
    assert found["reason"] == "source_ip"
    assert found["case_id"] == parent["id"]

    attached = store.attach_alert(
        parent["id"],
        alert_id="a2",
        rule_id="100102",
        source_ip="198.51.100.10",
        actor_user="bob",
        severity="medium",
        description="another block",
    )
    assert attached["attached"] is True
    assert attached["severity_rose"] is False
    assert attached["notify"] is False
    again = store.get_case(parent["id"])
    assert again["alert_id"] == "a1"
    situation = store.situation()
    assert situation["group_count"] == 1
    assert situation["groups"][0]["alert_count"] == 2
    assert situation["groups"][0]["source_ip"] == "198.51.100.10"
    assert situation["groups"][0]["top_rule"] == "100102"


def test_user_joins_when_ip_missing(tmp_path: Path) -> None:
    store = CaseStore(tmp_path / "cases.sqlite")
    parent = _open(store, alert_id="u1", source_ip=None, user="alice", severity="low")
    found = store.find_open_incident(source_ip=None, actor_user="alice")
    assert found["match"] is True
    assert found["reason"] == "user"
    assert found["case_id"] == parent["id"]


def test_no_actor_does_not_join(tmp_path: Path) -> None:
    store = CaseStore(tmp_path / "cases.sqlite")
    _open(store, alert_id="n1", source_ip=None, user=None)
    _open(store, alert_id="n2", source_ip=None, user=None)
    found = store.find_open_incident(source_ip=None, actor_user=None)
    assert found["match"] is False
    assert found["reason"] == "no_actor"
    situation = store.situation()
    assert situation["group_count"] == 0
    assert situation["ungrouped_open"] == 2


def test_outside_window_does_not_join(tmp_path: Path) -> None:
    store = CaseStore(tmp_path / "cases.sqlite")
    parent = _open(store, alert_id="old", source_ip="198.51.100.11", user=None)
    stale = (datetime.now(timezone.utc) - timedelta(hours=8)).isoformat()
    with store._connect() as conn:
        conn.execute(
            "UPDATE cases SET updated_at = ?, created_at = ? WHERE id = ?",
            (stale, stale, parent["id"]),
        )
    found = store.find_open_incident(source_ip="198.51.100.11", hours=6)
    assert found["match"] is False


def test_severity_rise_is_the_only_extra_page(tmp_path: Path) -> None:
    store = CaseStore(tmp_path / "cases.sqlite")
    parent = _open(store, alert_id="s1", source_ip="198.51.100.12", user=None, severity="medium")
    quiet = store.attach_alert(
        parent["id"],
        alert_id="s2",
        rule_id="100102",
        source_ip="198.51.100.12",
        severity="low",
    )
    assert quiet["severity_rose"] is False
    assert autonomy_loop.should_page_discord(opened_new=False, severity_rose=False) is False

    rose = store.attach_alert(
        parent["id"],
        alert_id="s3",
        rule_id="100101",
        source_ip="198.51.100.12",
        severity="critical",
    )
    assert rose["severity_rose"] is True
    assert rose["notify"] is True
    assert rose["previous_severity"] == "medium"
    assert store.get_case(parent["id"])["severity"] == "critical"
    assert autonomy_loop.should_page_discord(opened_new=False, severity_rose=True) is True
    assert autonomy_loop.should_page_discord(opened_new=True, severity_rose=False) is True


def test_closed_case_is_not_an_incident(tmp_path: Path) -> None:
    store = CaseStore(tmp_path / "cases.sqlite")
    parent = _open(store, alert_id="c1", source_ip="198.51.100.13", user=None)
    store.resolve_proposal(parent["id"], disposition="benign", note="done")
    found = store.find_open_incident(source_ip="198.51.100.13")
    assert found["match"] is False


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    settings = Settings(cases_db_path=str(tmp_path / "cases.sqlite"))
    monkeypatch.setattr(api_mod, "get_tools", lambda: SocTools(settings=settings))
    return TestClient(api_mod.app)


def test_situation_api(client: TestClient) -> None:
    opened = client.post(
        "/tools/open_case",
        json={
            "title": "scan",
            "alert_id": "api-a",
            "rule_id": "100102",
            "source_ip": "198.51.100.20",
            "severity": "high",
            "brief": {
                "headline": "scan",
                "actors": {"source_ip": "198.51.100.20", "user": None, "agent": "lab"},
            },
        },
    )
    assert opened.status_code == 200
    body = client.get("/tools/situation")
    assert body.status_code == 200
    data = body.json()
    assert data["group_count"] == 1
    assert data["groups"][0]["source_ip"] == "198.51.100.20"
    assert data["groups"][0]["alert_count"] >= 1
