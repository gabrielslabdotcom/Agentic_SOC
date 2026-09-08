"""SQLite entity correlation: upsert + find_related (same IP → two cases)."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from agentic_soc import api as api_mod
from agentic_soc.cases import CaseStore
from agentic_soc.config import Settings
from agentic_soc.tools import SocTools


def test_upsert_entity_idempotent(tmp_path: Path) -> None:
    store = CaseStore(tmp_path / "cases.sqlite")
    first = store.upsert_entity("ip", "192.168.50.99")
    second = store.upsert_entity("IP", "192.168.50.99")
    assert first["id"] == second["id"]
    assert first["entity_type"] == "ip"
    assert first["value"] == "192.168.50.99"


def test_find_related_same_ip_two_cases(tmp_path: Path) -> None:
    store = CaseStore(tmp_path / "cases.sqlite")
    c1 = store.open_case(title="nmap one", alert_id="alert-1", agent_name="pop-os-native")
    c2 = store.open_case(title="nmap two", alert_id="alert-2", agent_name="pop-os-native")
    entity = store.upsert_entity("ip", "192.168.50.99")
    store.link_alert_to_entity(entity["id"], "alert-1", case_id=c1["id"])
    store.link_case_to_entity(entity["id"], c2["id"], alert_id="alert-2")

    related = store.find_related(case_id=c1["id"])
    ids = [c["id"] for c in related["related_cases"]]
    assert c2["id"] in ids
    assert c1["id"] not in ids
    assert related["count"] == 1
    matched = related["related_cases"][0]["matched_entities"]
    assert any(e["value"] == "192.168.50.99" for e in matched)

    by_ip = store.find_related(entity_type="ip", value="192.168.50.99")
    by_ip_ids = {c["id"] for c in by_ip["related_cases"]}
    assert by_ip_ids == {c1["id"], c2["id"]}


def test_find_related_host_not_followed_from_case(tmp_path: Path) -> None:
    store = CaseStore(tmp_path / "cases.sqlite")
    c1 = store.open_case(title="host a")
    c2 = store.open_case(title="host b")
    host = store.upsert_entity("host", "pop-os-native")
    store.link_case_to_entity(host["id"], c1["id"])
    store.link_case_to_entity(host["id"], c2["id"])

    related = store.find_related(case_id=c1["id"])
    assert related["related_cases"] == []

    with_hosts = store.find_related(case_id=c1["id"], include_hosts=True)
    assert any(c["id"] == c2["id"] for c in with_hosts["related_cases"])


def test_correlate_alert_links_source_ip(tmp_path: Path) -> None:
    settings = Settings(cases_db_path=str(tmp_path / "cases.sqlite"))
    tools = SocTools(settings=settings)
    alert = {
        "id": "alert-1",
        "agent": "pop-os-native",
        "full_log": "[UFW BLOCK] SRC=192.168.50.99 DST=192.168.50.254 DPT=22",
        "description": "Possible port scan (lab)",
    }
    c1 = tools.open_case(title="scan 1", alert_id="alert-1", agent_name="pop-os-native")
    tools.correlate_alert(alert, case_id=c1["id"], alert_id="alert-1")

    alert2 = {**alert, "id": "alert-2"}
    c2 = tools.open_case(title="scan 2", alert_id="alert-2", agent_name="pop-os-native")
    tools.correlate_alert(alert2, case_id=c2["id"], alert_id="alert-2")

    related = tools.find_related(case_id=c1["id"])
    assert any(c["id"] == c2["id"] for c in related["related_cases"])


def test_find_related_api(tmp_path: Path, monkeypatch) -> None:
    db = tmp_path / "cases.sqlite"
    settings = Settings(cases_db_path=str(db))
    tools = SocTools(settings=settings)
    monkeypatch.setattr(api_mod, "get_tools", lambda: tools)
    client = TestClient(api_mod.app)

    c1 = client.post("/tools/open_case", json={"title": "one"}).json()
    c2 = client.post("/tools/open_case", json={"title": "two"}).json()
    ent = client.post("/tools/upsert_entity", json={"entity_type": "ip", "value": "10.1.2.3"}).json()
    client.post(
        "/tools/link_case_to_entity",
        json={"entity_id": ent["id"], "case_id": c1["id"]},
    )
    client.post(
        "/tools/link_case_to_entity",
        json={"entity_id": ent["id"], "case_id": c2["id"]},
    )

    related = client.get(f"/tools/find_related?case_id={c1['id']}")
    assert related.status_code == 200
    ids = [c["id"] for c in related.json()["related_cases"]]
    assert c2["id"] in ids
    assert c1["id"] not in ids


def test_unique_alert_id_returns_existing(tmp_path: Path) -> None:
    store = CaseStore(tmp_path / "cases.sqlite")
    first = store.open_case(title="one", alert_id="alert-dup")
    second = store.open_case(title="two", alert_id="alert-dup")
    assert first["id"] == second["id"]
    assert second.get("duplicate") is True
    listed = store.list_cases(limit=10)
    assert listed["count"] == 1


def test_null_alert_ids_can_repeat(tmp_path: Path) -> None:
    store = CaseStore(tmp_path / "cases.sqlite")
    a = store.open_case(title="manual a")
    b = store.open_case(title="manual b")
    assert a["id"] != b["id"]
