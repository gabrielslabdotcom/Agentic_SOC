"""Analyst brief: actor extraction and HITL shape."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentic_soc import api as api_mod
from agentic_soc.cases import CaseStore
from agentic_soc.config import Settings
from agentic_soc.discord_notify import DiscordNotifier
from agentic_soc.tools import SocTools
from agentic_soc.triage import (
    build_analyst_brief,
    extract_source_ip,
    extract_user,
    score_alert,
)


def _alert(**kwargs: object) -> dict:
    rule_id = str(kwargs.get("rule_id") or "2501")
    desc = str(kwargs.get("description") or "syslog: User authentication failure.")
    full = str(kwargs.get("full_log") or "")
    groups = kwargs.get("groups") or ["syslog", "authentication_failed"]
    data = kwargs.get("data")
    raw: dict = {
        "rule": {"id": rule_id, "level": kwargs.get("rule_level") or 5, "description": desc, "groups": groups},
        "full_log": full,
    }
    if isinstance(data, dict):
        raw["data"] = data
    return {
        "id": "a1",
        "rule_id": rule_id,
        "rule_level": kwargs.get("rule_level") or 5,
        "description": desc,
        "full_log": full,
        "agent": kwargs.get("agent") or "lab-agent",
        "raw": raw,
    }


def test_sshd_from_ip_and_invalid_user() -> None:
    alert = _alert(
        rule_id="5710",
        description="sshd: Attempt to login using a non-existent user",
        full_log="Invalid user labprobe from 198.51.100.30 port 22",
        groups=["sshd", "authentication_failed"],
    )
    assert extract_source_ip(alert) == "198.51.100.30"
    assert extract_user(alert) == "labprobe"


def test_pam_user_and_rhost() -> None:
    alert = _alert(
        full_log="pam_unix(sshd:auth): authentication failure; rhost=192.168.50.20 user=admin",
    )
    assert extract_source_ip(alert) == "192.168.50.20"
    assert extract_user(alert) == "admin"


def test_ufw_src_kept_even_if_private() -> None:
    alert = _alert(
        rule_id="100100",
        description="UFW BLOCK",
        full_log="[UFW BLOCK] SRC=10.1.2.3 DST=10.0.0.5",
        groups=["firewall"],
    )
    assert extract_source_ip(alert) == "10.1.2.3"
    assert extract_user(alert) is None


def test_brief_has_three_steps_and_no_execute() -> None:
    alert = _alert(full_log="pam_unix(sshd:auth): authentication failure; user=bob rhost=203.0.113.9")
    judgment = score_alert(alert)
    brief = build_analyst_brief(
        alert,
        judgment,
        [{"ioc": "203.0.113.9", "malicious": 2, "suspicious": 0}],
        wazuh_dashboard_url="https://siem.example/",
    )
    assert brief["actors"]["source_ip"] == "203.0.113.9"
    assert brief["actors"]["user"] == "bob"
    assert len(brief["do_next"]) == 3
    joined = " ".join(brief["do_next"]).lower()
    assert "execute" not in joined or "do not execute" in joined
    assert brief["vt"].startswith("203.0.113.9")
    assert brief["wazuh_url"] == "https://siem.example"
    assert len(brief["evidence"]) <= 200


def test_missing_actors_still_brief() -> None:
    alert = _alert(full_log="authentication failure")
    brief = build_analyst_brief(alert, score_alert(alert))
    assert brief["actors"]["source_ip"] is None
    assert brief["actors"]["user"] is None
    assert len(brief["do_next"]) == 3
    assert "any source" in brief["do_next"][2]


def test_get_case_returns_stored_and_fallback_brief(tmp_path: Path) -> None:
    store = CaseStore(tmp_path / "cases.sqlite")
    opened = store.open_case(
        title="auth",
        alert_id="z1",
        rule_id="2501",
        source_ip="198.51.100.8",
        summary="description=syslog: User authentication failure.",
        brief={"headline": "Failed login", "actors": {"user": "alice", "source_ip": "198.51.100.8", "agent": "lab"}},
    )
    assert opened["brief"]["headline"] == "Failed login"
    assert opened["brief"]["actors"]["user"] == "alice"

    legacy = store.open_case(
        title="[auto][suspicious] syslog: User authentication failure.",
        alert_id="z2",
        rule_id="2501",
        summary="description=syslog: User authentication failure.",
    )
    assert legacy["brief"]["rebuilt"] is True
    assert len(legacy["brief"]["do_next"]) == 3


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    settings = Settings(cases_db_path=str(tmp_path / "cases.sqlite"), wazuh_dashboard_url="https://example.test")
    monkeypatch.setattr(api_mod, "get_tools", lambda: SocTools(settings=settings))
    return TestClient(api_mod.app)


def test_api_get_case_includes_brief(client: TestClient) -> None:
    opened = client.post(
        "/tools/open_case",
        json={
            "title": "scan",
            "alert_id": "api-1",
            "rule_id": "100102",
            "source_ip": "198.51.100.21",
            "brief": {
                "headline": "Repeated UFW blocks",
                "actors": {"source_ip": "198.51.100.21", "user": None, "agent": "lab-agent"},
                "do_next": ["a", "b", "c"],
            },
        },
    )
    assert opened.status_code == 200
    body = client.get(f"/tools/get_case/{opened.json()['id']}")
    assert body.status_code == 200
    assert body.json()["brief"]["headline"] == "Repeated UFW blocks"


def test_discord_embed_leads_with_brief() -> None:
    notifier = DiscordNotifier(Settings(discord_webhook_url="", wazuh_dashboard_url="https://siem.example"))
    embed = notifier._case_opened_embed(
        {
            "id": 9,
            "title": "old title",
            "disposition": "suspicious",
            "severity": "medium",
            "rule_id": "5710",
            "rule_level": 5,
            "timestamp": "2026-09-15T12:00:00Z",
            "agent_name": "lab-agent",
            "brief": {
                "headline": "sshd invalid user",
                "actors": {"source_ip": "198.51.100.30", "user": "labprobe", "agent": "lab-agent"},
                "why": ["explicit authentication failure signal"],
                "evidence": "Invalid user labprobe from 198.51.100.30",
                "vt": "",
                "do_next": ["Confirm the failed login.", "Close as Benign.", "Suppress if it repeats."],
                "wazuh_url": "https://siem.example",
                "recommended_action": "investigate_and_document",
            },
        }
    )
    names = [f["name"] for f in embed["fields"]]
    assert names[:4] == ["Disposition", "Severity", "Source", "User"]
    assert "Analyst outcomes" not in names
    assert "Close (CLI)" not in names
    assert embed["description"] == "sshd invalid user"
    assert any(f["name"] == "Do next" for f in embed["fields"])
