"""Ask Pop search: query builders, tool loop, keyword fallback, cases."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

from fastapi.testclient import TestClient

from agentic_soc import api as api_mod
from agentic_soc.cases import CaseStore
from agentic_soc.config import Settings
from agentic_soc.search import (
    AUTH_RULE_GROUPS,
    MAX_HOURS,
    SearchEngine,
    build_alert_text_clause,
    build_alerts_query,
    build_inventory_query,
    build_vulnerabilities_query,
    resolve_agent_name,
)
from agentic_soc.tools import SocTools
from agentic_soc.wazuh_client import ALLOWED_INDEX_PATTERNS, WazuhClient
import pytest


def test_alerts_user_or_fields() -> None:
    body = build_alerts_query({"user": "tstark", "hours": 24, "limit": 10})
    must = body["query"]["bool"]["must"]
    user_clause = next(c for c in must if "bool" in c and "should" in c["bool"])
    fields = {list(s["match"].keys())[0] for s in user_clause["bool"]["should"]}
    assert "data.srcuser" in fields
    assert "data.dstuser" in fields
    assert "data.win.eventdata.targetUserName" in fields
    assert "data.win.eventdata.subjectUserName" in fields


def test_alerts_hours_capped() -> None:
    body = build_alerts_query({"hours": 99999})
    must = body["query"]["bool"]["must"]
    ranges = [c for c in must if "range" in c]
    assert ranges[0]["range"]["@timestamp"]["gte"] == f"now-{MAX_HOURS}h"


def test_alerts_group_by() -> None:
    body = build_alerts_query({"group_by": "agent", "limit": 5})
    assert body["size"] == 0
    assert body["aggs"]["by"]["terms"]["field"] == "agent.name"
    assert body["aggs"]["by"]["terms"]["size"] == 5


def test_inventory_field_allowlist_rejects() -> None:
    with pytest.raises(ValueError, match="field not allowed"):
        build_inventory_query(
            {
                "category": "ports",
                "field_filters": {"evil.field": "1"},
            }
        )


def test_inventory_port_filter() -> None:
    index, body = build_inventory_query(
        {
            "category": "ports",
            "agent": "windows-workstation",
            "field_filters": {"destination.port": "3389"},
        }
    )
    assert index == "wazuh-states-inventory-ports-*"
    assert index in ALLOWED_INDEX_PATTERNS
    must = body["query"]["bool"]["must"]
    assert any(c.get("term", {}).get("agent.name") == "windows-workstation" for c in must)
    assert any(c.get("term", {}).get("destination.port") == 3389 for c in must)


def test_inventory_unknown_category() -> None:
    with pytest.raises(ValueError, match="unknown inventory category"):
        build_inventory_query({"category": "archives"})


def test_vulnerabilities_query() -> None:
    body = build_vulnerabilities_query(
        {"agent": "domain-controller", "severity": "Critical", "limit": 10}
    )
    must = body["query"]["bool"]["must"]
    assert any(c.get("term", {}).get("agent.name") == "domain-controller" for c in must)
    assert any(c.get("term", {}).get("vulnerability.severity") == "Critical" for c in must)
    assert body["size"] == 10


def test_resolve_agent_popos() -> None:
    known = ["siem-host", "windows-workstation", "domain-controller", "soc-windows"]
    assert resolve_agent_name("siemhost", known) == "siem-host"
    assert resolve_agent_name("SIEM-HOST", known) == "siem-host"
    assert resolve_agent_name("windows-workstation", known) == "windows-workstation"
    assert resolve_agent_name("unknown-box", known) == "unknown-box"


def test_alerts_agent_uses_term() -> None:
    body = build_alerts_query({"agent": "siem-host", "hours": 6})
    must = body["query"]["bool"]["must"]
    assert {"term": {"agent.name": "siem-host"}} in must


def test_alerts_login_text_expands_auth() -> None:
    body = build_alerts_query({"agent": "siem-host", "hours": 6, "text": "login"})
    must = body["query"]["bool"]["must"]
    text_clause = next(
        c for c in must if isinstance(c.get("bool"), dict) and "should" in c["bool"]
    )
    should = text_clause["bool"]["should"]
    assert any("simple_query_string" in s for s in should)
    assert any(
        s.get("wildcard", {}).get("rule.description") == "*login*" for s in should
    )
    groups = next(s for s in should if "terms" in s and "rule.groups" in s["terms"])
    assert set(groups["terms"]["rule.groups"]) == set(AUTH_RULE_GROUPS)


def test_alert_text_clause_helper() -> None:
    clause = build_alert_text_clause("login")
    should = clause["bool"]["should"]
    assert len(should) >= 3


def test_search_index_rejects_unknown_pattern() -> None:
    client = WazuhClient(Settings())

    async def _run() -> dict[str, Any]:
        return await client.search_index(
            "wazuh-archives-*", {"size": 1, "query": {"match_all": {}}}
        )

    result = asyncio.run(_run())
    assert result["ok"] is False
    assert result["error"] == "index_not_allowed"


def test_search_cases_like(tmp_path: Path) -> None:
    store = CaseStore(tmp_path / "cases.sqlite")
    opened = store.open_case(
        title="Failed login for tstark",
        summary="Windows auth noise",
        agent_name="domain-controller",
        source_ip="198.51.100.50",
        rule_id="60122",
    )
    store.update_case(opened["id"], note="saw tstark from Kali", author="test")
    ent = store.upsert_entity("user", "tstark")
    store.link_case_to_entity(int(ent["id"]), int(opened["id"]))

    by_text = store.search_cases(text="tstark")
    assert by_text["count"] >= 1
    assert any(c["id"] == opened["id"] for c in by_text["cases"])

    by_user = store.search_cases(user="tstark")
    assert by_user["count"] >= 1

    by_ip = store.search_cases(source_ip="198.51.100.50")
    assert by_ip["count"] >= 1


def test_keyword_fallback_no_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings(
        cases_db_path=str(tmp_path / "cases.sqlite"),
        anthropic_api_key="",
    )
    store = CaseStore(settings.cases_path)
    store.open_case(title="port scan from lab", summary="nmap noise", agent_name="siem-host")

    engine = SearchEngine(settings=settings, cases=store)

    async def fake_alerts(args: dict[str, Any]) -> dict[str, Any]:
        return {
            "ok": True,
            "source": "alerts",
            "total": 1,
            "count": 1,
            "rows": [{"id": "a1", "description": "port scan", "agent": "siem-host"}],
        }

    monkeypatch.setattr(engine, "_search_alerts", fake_alerts)
    result = asyncio.run(engine.run_search("port scan"))
    assert result["mode"] == "keyword"
    assert result["model"] is None
    assert "keyword" in (result["answer"] or "").lower() or "Anthropic" in (result["answer"] or "")
    assert result["results"]["alerts"]
    assert result["results"]["cases"]


def test_llm_tool_loop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings(
        cases_db_path=str(tmp_path / "cases.sqlite"),
        anthropic_api_key="sk-ant-test",
        anthropic_model="claude-haiku-4-5",
    )
    store = CaseStore(settings.cases_path)
    engine = SearchEngine(settings=settings, cases=store)

    async def fake_list_agents(limit: int = 100) -> dict[str, Any]:
        return {"agents": [{"name": "windows-workstation", "status": "active"}], "total": 1}

    monkeypatch.setattr(engine.wazuh, "list_agents", fake_list_agents)

    calls = {"n": 0}

    async def fake_complete(**kwargs: Any) -> dict[str, Any]:
        calls["n"] += 1
        if calls["n"] == 1:
            return {
                "stop_reason": "tool_use",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "toolu_1",
                        "name": "search_inventory",
                        "input": {
                            "category": "ports",
                            "field_filters": {"destination.port": "3389"},
                        },
                    }
                ],
            }
        return {
            "stop_reason": "end_turn",
            "content": [
                {
                    "type": "text",
                    "text": "windows-workstation listens on 3389 (RDP).",
                }
            ],
        }

    monkeypatch.setattr("agentic_soc.search.complete_messages", fake_complete)

    async def fake_search_index(index: str, body: dict[str, Any]) -> dict[str, Any]:
        assert index == "wazuh-states-inventory-ports-*"
        return {
            "ok": True,
            "index": index,
            "total": 1,
            "count": 1,
            "hits": [
                {
                    "id": "1",
                    "source": {
                        "agent": {"name": "windows-workstation"},
                        "destination": {"port": 3389},
                        "process": {"name": "svchost.exe"},
                    },
                }
            ],
            "aggregations": {},
        }

    monkeypatch.setattr(engine.wazuh, "search_index", fake_search_index)

    result = asyncio.run(engine.run_search("which hosts listen on 3389"))
    assert result["mode"] == "llm"
    assert result["model"] == "claude-haiku-4-5"
    assert "3389" in (result["answer"] or "")
    assert result["steps"]
    assert result["steps"][0]["tool"] == "search_inventory"
    assert result["results"]["inventory"]
    assert calls["n"] == 2


def test_round_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings(
        cases_db_path=str(tmp_path / "cases.sqlite"),
        anthropic_api_key="sk-ant-test",
    )
    engine = SearchEngine(settings=settings, cases=CaseStore(settings.cases_path))
    monkeypatch.setattr(
        engine.wazuh,
        "list_agents",
        AsyncMock(return_value={"agents": [], "total": 0}),
    )

    async def always_tool(**kwargs: Any) -> dict[str, Any]:
        if not kwargs.get("tools"):
            return {
                "stop_reason": "end_turn",
                "content": [{"type": "text", "text": "Stopped after max rounds."}],
            }
        return {
            "stop_reason": "tool_use",
            "content": [
                {
                    "type": "tool_use",
                    "id": "toolu_x",
                    "name": "list_agents",
                    "input": {},
                }
            ],
        }

    monkeypatch.setattr("agentic_soc.search.complete_messages", always_tool)
    monkeypatch.setattr(
        engine,
        "_list_agents",
        AsyncMock(return_value={"ok": True, "source": "agents", "count": 0, "total": 0, "rows": []}),
    )

    result = asyncio.run(engine.run_search("list everything forever"))
    assert result["mode"] == "llm"
    assert "Stopped" in (result["answer"] or "") or result.get("stop_reason")
    assert len(result["steps"]) == 4


def test_api_search_endpoint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CASES_DB_PATH", str(tmp_path / "cases.sqlite"))
    api_mod._api_tools = None

    async def fake_search(self: SocTools, question: str) -> dict[str, Any]:
        return {
            "ok": True,
            "mode": "keyword",
            "model": None,
            "answer": f"echo:{question}",
            "steps": [],
            "results": {
                "alerts": [],
                "inventory": [],
                "vulnerabilities": [],
                "cases": [],
                "agents": [],
                "buckets": [],
            },
        }

    monkeypatch.setattr(SocTools, "search", fake_search)
    client = TestClient(api_mod.app)
    resp = client.post("/tools/search", json={"question": "hello lab"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["answer"] == "echo:hello lab"
    assert body["mode"] == "keyword"


def test_anthropic_extractors() -> None:
    from agentic_soc.anthropic_llm import extract_text, extract_tool_uses

    payload = {
        "content": [
            {"type": "text", "text": "hello"},
            {
                "type": "tool_use",
                "id": "1",
                "name": "search_alerts",
                "input": {"text": "ssh"},
            },
        ]
    }
    assert extract_text(payload) == "hello"
    uses = extract_tool_uses(payload)
    assert uses[0]["name"] == "search_alerts"
    assert uses[0]["input"]["text"] == "ssh"


def test_anthropic_connector_independent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTIC_SOC_DATA", str(tmp_path))
    from agentic_soc.connectors import public_catalog, save_connector
    from agentic_soc.config import get_settings

    save_connector(
        "openai",
        enabled=True,
        config={
            "openai_base_url": "https://api.openai.com/v1",
            "openai_api_key": "sk-test-9999",
            "openai_model": "gpt-4o-mini",
        },
    )
    save_connector(
        "anthropic",
        enabled=True,
        config={
            "anthropic_api_key": "sk-ant-lab",
            "anthropic_base_url": "https://api.anthropic.com",
            "anthropic_model": "claude-haiku-4-5",
        },
    )
    body = public_catalog()
    by_id = {card["id"]: card for card in body["connectors"]}
    assert by_id["openai"]["enabled"] is True
    assert by_id["anthropic"]["enabled"] is True
    assert by_id["anthropic"]["kind"] == "search_llm"
    settings = get_settings()
    assert settings.llm_connector == "openai"
    assert settings.anthropic_api_key == "sk-ant-lab"
    assert settings.anthropic_model == "claude-haiku-4-5"
