"""Read-only incident packet and deterministic meaning note."""

from __future__ import annotations

import asyncio
from pathlib import Path

from agentic_soc.cases import CaseStore
from agentic_soc.config import Settings
from agentic_soc.cursor_agent import (
    MEANING_AUTHOR,
    MEANING_PREFIX,
    build_incident_packet,
    build_investigation_prompt,
    persist_meaning_note,
    render_meaning_note,
    should_explain_incident,
)


class _FakeTools:
    def __init__(self, case: dict) -> None:
        self.case = case
        self.calls: list[str] = []

    def get_case(self, case_id: int) -> dict:
        self.calls.append("get_case")
        return self.case

    def find_related(self, **kwargs: object) -> dict:
        self.calls.append("find_related")
        return {
            "related_cases": [
                {"id": 9, "title": "earlier scan", "status": "open", "rule_id": "100102", "source_ip": "198.51.100.10"}
            ]
        }

    async def get_alert(self, alert_id: str) -> dict:
        self.calls.append("get_alert")
        return {
            "id": alert_id,
            "rule_id": "100102",
            "description": "Possible port scan",
            "full_log": "SRC=198.51.100.10",
            "timestamp": "2026-09-23T12:00:00Z",
        }

    async def list_alerts(self, **kwargs: object) -> dict:
        self.calls.append("list_alerts")
        return {
            "alerts": [
                {"id": "near-1", "rule_id": "100100", "description": "UFW block", "timestamp": "2026-09-23T11:59:00Z"}
            ]
        }


def _case() -> dict:
    return {
        "id": 4,
        "title": "port scan",
        "status": "open",
        "disposition": "suspicious",
        "severity": "high",
        "rule_id": "100102",
        "source_ip": "198.51.100.10",
        "actor_user": None,
        "agent_name": "lab-agent",
        "alert_id": "a1",
        "alert_count": 2,
        "brief": {
            "headline": "Repeated UFW blocks",
            "actors": {"source_ip": "198.51.100.10", "user": None, "agent": "lab-agent"},
            "why": ["aggregated port-scan rule"],
            "evidence": "SRC=198.51.100.10",
            "do_next": ["Confirm in Wazuh.", "Close as Benign or Confirmed.", "Suppress if it repeats."],
        },
    }


def test_packet_cites_related_and_brief_without_actions() -> None:
    tools = _FakeTools(_case())
    packet = asyncio.run(build_incident_packet(
        tools,
        case_id=4,
        alert_id="a1",
        enrichments=[{"ioc": "198.51.100.10", "malicious": 0, "suspicious": 1}],
    ))
    assert packet["ok"] is True
    assert packet["related_case_ids"] == [9]
    assert packet["brief"]["headline"] == "Repeated UFW blocks"
    assert packet["alert_count"] == 2
    assert packet["nearby_alerts"][0]["id"] == "near-1"
    assert packet["tools_used"] == ["get_case", "find_related", "get_alert", "list_alerts"]
    blob = str(packet)
    assert "approve_case" not in blob
    assert "execute_containment" not in blob
    assert "propose_action" not in blob


def test_meaning_note_has_four_parts(tmp_path: Path) -> None:
    packet = {
        "case_id": 4,
        "title": "port scan",
        "disposition": "suspicious",
        "severity": "high",
        "source_ip": "198.51.100.10",
        "alert_count": 2,
        "related_case_ids": [9],
        "brief": _case()["brief"],
        "trigger_alert": {"evidence": "SRC=198.51.100.10"},
        "enrichments": [],
    }
    note = render_meaning_note(packet)
    assert note.startswith(MEANING_PREFIX)
    assert "What it means" in note
    assert "Evidence" in note
    assert "Related cases" in note
    assert "#9" in note
    assert "Next steps" in note
    assert "containment=not_executed" in note
    settings = Settings(
        cases_db_path=str(tmp_path / "cases.sqlite"),
        wazuh_api_password="x",
        wazuh_indexer_password="x",
    )
    store = CaseStore(settings.cases_path)
    opened = store.open_case(title="port scan", alert_id="a1", source_ip="198.51.100.10")
    saved = persist_meaning_note(opened["id"], packet, settings=settings)
    assert saved["ok"] is True
    last = store.get_case(opened["id"])["notes"][-1]
    assert last["author"] == MEANING_AUTHOR
    assert "#9" in last["note"]


def test_prompt_is_packet_only() -> None:
    packet = {"case_id": 4, "brief": {"headline": "Repeated UFW blocks"}, "related_case_ids": [9]}
    prompt = build_investigation_prompt({"id": 4}, api_url="http://192.168.50.254:8080", packet=packet)
    assert "Repeated UFW blocks" in prompt
    assert "related_case_ids" in prompt
    assert "Do **not** call Wazuh" in prompt
    assert "Do **not** approve" in prompt
    assert "192.168.50.254" not in prompt
    assert "update_case" not in prompt
    assert "execute_containment" not in prompt


def test_explain_only_on_open_or_severity_rise() -> None:
    assert should_explain_incident(opened_new=True, severity_rose=False) is True
    assert should_explain_incident(opened_new=False, severity_rose=True) is True
    assert should_explain_incident(opened_new=False, severity_rose=False) is False


def _alert(alert_id: str) -> dict:
    return {
        "id": alert_id,
        "rule_id": "100102",
        "rule_level": 10,
        "description": "Possible port scan",
        "full_log": "SRC=198.51.100.10",
        "agent": "lab-agent",
        "timestamp": "2026-09-23T12:00:00.000Z",
    }


class _CycleTools:
    def __init__(self, scenario: str, alert: dict) -> None:
        self.scenario = scenario
        self.alert = alert
        self.settings = Settings(
            cases_db_path="data/cases.sqlite",
            discord_webhook_url="",
            wazuh_dashboard_url="https://example.test",
        )

    def known_alert_ids(self) -> set[str]:
        return set()

    async def list_alerts(self, **kwargs: object) -> dict:
        return {"alerts": [self.alert], "total": 1}

    def match_suppression(self, **kwargs: object) -> dict:
        return {"match": False}

    def find_open_incident(self, **kwargs: object) -> dict:
        if self.scenario == "open":
            return {"match": False}
        return {"match": True, "case_id": 7, "case": {"id": 7, "title": "scan"}}

    def attach_alert(self, *args: object, **kwargs: object) -> dict:
        rose = self.scenario == "rise"
        return {
            "attached": True,
            "notify": rose,
            "severity_rose": rose,
            "previous_severity": "medium",
            "severity": "high" if rose else "medium",
            "case": {"id": 7, "title": "scan"},
        }

    def correlate_alert(self, *args: object, **kwargs: object) -> dict:
        return {"count": 0}

    def open_case(self, **kwargs: object) -> dict:
        return {"id": 11, "title": kwargs.get("title")}

    def update_case(self, *args: object, **kwargs: object) -> dict:
        return {"id": 11}

    def propose_action(self, case_id: int, action: str, rationale: str = "") -> dict:
        return {
            "id": case_id,
            "title": "scan",
            "disposition": "true_positive",
            "severity": "high",
            "recommended_action": action,
            "agent_name": "lab-agent",
        }

    def plan_containment(self, **kwargs: object) -> dict:
        return {"allowed": False}


def _cycle_args() -> object:
    import argparse

    return argparse.Namespace(
        limit=10,
        min_level=8,
        agent_name=None,
        exclude_ufw_blocks=True,
        include_auth=False,
        auth_min_level=5,
        feedback_skip=False,
        auto_close_noise=True,
        enrich=False,
        discord=False,
        cursor_agent=False,
        cursor_dry_run=False,
        max_cases=10,
        incident_hours=6,
    )


def _load_autonomy():
    import importlib.util

    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "autonomy_loop_meaning",
        root / "scripts" / "autonomy_loop.py",
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_autonomy_explains_on_open_and_severity_rise_not_quiet_attach(monkeypatch) -> None:
    loop = _load_autonomy()
    explained: list[int] = []

    async def fake_explain(tools, case, **kwargs):  # noqa: ANN001
        explained.append(int(case["id"]))
        return {"ok": True, "meaning_note": {"ok": True}, "cursor": {"skipped": True}}

    monkeypatch.setattr(loop, "explain_incident", fake_explain)
    for scenario, alert_id, expect in (
        ("open", "alert-open", [11]),
        ("quiet", "alert-quiet", []),
        ("rise", "alert-rise", [7]),
    ):
        explained.clear()
        monkeypatch.setattr(
            loop,
            "SocTools",
            lambda s=scenario, a=alert_id, **kwargs: _CycleTools(s, _alert(a)),
        )
        report = asyncio.run(loop.run_cycle(_cycle_args(), {}))
        assert explained == expect, scenario
        if scenario == "quiet":
            assert report["severity_rose"] == 0
            assert report["attached"] == 1
        if scenario == "rise":
            assert report["severity_rose"] == 1
        if scenario == "open":
            assert report["cases_opened"]
