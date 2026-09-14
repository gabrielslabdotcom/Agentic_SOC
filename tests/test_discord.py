"""Unit tests for Discord outcome buttons (no live Discord)."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentic_soc.analyst_outcomes import (
    BENIGN,
    CONFIRMED_COMPROMISE,
    FALSE_POSITIVE,
)
from agentic_soc.cases import CaseStore
from agentic_soc.config import Settings
from agentic_soc.discord_bot import (
    handle_outcome_click,
    interaction_allowed,
)
from agentic_soc.discord_notify import (
    DiscordNotifier,
    analyst_ui_base_url,
    build_outcome_components,
    outcome_custom_id,
    parse_outcome_custom_id,
)


def test_outcome_custom_id_roundtrip() -> None:
    cid = outcome_custom_id(FALSE_POSITIVE, 42)
    assert cid == "soc:false_positive:42"
    disposition, case_id = parse_outcome_custom_id(cid)
    assert disposition == FALSE_POSITIVE
    assert case_id == 42


def test_parse_outcome_custom_id_rejects_bad() -> None:
    with pytest.raises(ValueError):
        parse_outcome_custom_id("approve:1")
    with pytest.raises(ValueError):
        parse_outcome_custom_id("soc:not_a_real:1")
    with pytest.raises(ValueError):
        parse_outcome_custom_id("soc:benign:nope")
    with pytest.raises(ValueError, match="must be >= 1"):
        parse_outcome_custom_id("soc:benign:0")
    with pytest.raises(ValueError, match="must be >= 1"):
        parse_outcome_custom_id("soc:confirmed_compromise:-1")


def test_build_outcome_components_rejects_invalid_id() -> None:
    with pytest.raises(ValueError, match="must be >= 1"):
        build_outcome_components(0)
    with pytest.raises(ValueError, match="must be >= 1"):
        outcome_custom_id(BENIGN, 0)


def test_build_outcome_components_five_buttons() -> None:
    rows = build_outcome_components(7)
    assert len(rows) == 1
    buttons = rows[0]["components"]
    assert len(buttons) == 5
    labels = [b["label"] for b in buttons]
    assert labels == [
        "False Positive",
        "Benign",
        "Informational",
        "Duplicate",
        "Confirmed Compromise",
    ]
    assert buttons[-1]["style"] == 4  # danger
    assert buttons[0]["custom_id"] == "soc:false_positive:7"
    assert buttons[-1]["custom_id"] == "soc:confirmed_compromise:7"


def test_analyst_ui_base_url_from_dashboard() -> None:
    settings = Settings(wazuh_dashboard_url="https://siem.lab.example")
    assert analyst_ui_base_url(settings) == "http://siem.lab.example:8080"


def test_bot_configured_vs_webhook(tmp_path: Path) -> None:
    bot = DiscordNotifier(
        Settings(
            cases_db_path=str(tmp_path / "c.sqlite"),
            discord_bot_token="tok",
            discord_channel_id="123",
            discord_webhook_url="",
        )
    )
    assert bot.bot_configured is True
    assert bot.configured is True

    hook = DiscordNotifier(
        Settings(
            cases_db_path=str(tmp_path / "c.sqlite"),
            discord_bot_token="",
            discord_channel_id="",
            discord_webhook_url="https://example.invalid/hook",
        )
    )
    assert hook.bot_configured is False
    assert hook.webhook_configured is True
    assert hook.configured is True


def test_notify_case_opened_uses_bot_rest(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    settings = Settings(
        cases_db_path=str(tmp_path / "c.sqlite"),
        discord_bot_token="test-token",
        discord_channel_id="999001",
        discord_webhook_url="",
        wazuh_dashboard_url="https://siem.example",
    )
    notifier = DiscordNotifier(settings)

    captured: dict = {}

    class FakeResp:
        status_code = 200

        def json(self):
            return {"id": "msg1", "channel_id": "999001"}

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

        async def post(self, url, json=None, headers=None):
            captured["url"] = url
            captured["json"] = json
            captured["headers"] = headers
            return FakeResp()

    import agentic_soc.discord_notify as mod

    monkeypatch.setattr(mod.httpx, "AsyncClient", FakeClient)

    result = asyncio.run(
        notifier.notify_case_opened(
            {
                "id": 15,
                "title": "Test case",
                "disposition": "suspicious",
                "severity": "high",
                "rule_id": "100102",
                "reasons": ["lab"],
            }
        )
    )
    assert result["ok"] is True
    assert result["via"] == "bot"
    assert captured["url"].endswith("/channels/999001/messages")
    assert captured["headers"]["Authorization"] == "Bot test-token"
    comps = captured["json"]["components"]
    assert len(comps[0]["components"]) == 5
    assert any(
        c["custom_id"] == "soc:benign:15" for c in comps[0]["components"]
    )


def test_notify_case_opened_webhook_has_no_components(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    settings = Settings(
        cases_db_path=str(tmp_path / "c.sqlite"),
        discord_bot_token="",
        discord_channel_id="",
        discord_webhook_url="https://example.invalid/hook",
    )
    notifier = DiscordNotifier(settings)
    captured: dict = {}

    class FakeResp:
        status_code = 204

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

        async def post(self, url, json=None, headers=None):
            captured["url"] = url
            captured["json"] = json
            return FakeResp()

    import agentic_soc.discord_notify as mod

    monkeypatch.setattr(mod.httpx, "AsyncClient", FakeClient)
    result = asyncio.run(
        notifier.notify_case_opened({"id": 3, "title": "x", "severity": "low"})
    )
    assert result["ok"] is True
    assert result["via"] == "webhook"
    assert "components" not in captured["json"]


def test_notify_case_opened_skips_buttons_for_invalid_id(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    settings = Settings(
        cases_db_path=str(tmp_path / "c.sqlite"),
        discord_bot_token="test-token",
        discord_channel_id="999001",
        discord_webhook_url="",
    )
    notifier = DiscordNotifier(settings)
    captured: dict = {}

    class FakeResp:
        status_code = 200

        def json(self):
            return {"id": "msg1"}

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

        async def post(self, url, json=None, headers=None):
            captured["json"] = json
            return FakeResp()

    import agentic_soc.discord_notify as mod

    monkeypatch.setattr(mod.httpx, "AsyncClient", FakeClient)

    for bad_id in (0, None, -3):
        captured.clear()
        result = asyncio.run(
            notifier.notify_case_opened(
                {"id": bad_id, "title": "bad id", "severity": "low"}
            )
        )
        assert result["ok"] is True
        assert "components" not in captured["json"]


def test_handle_outcome_click_rejects_case_id_zero(tmp_path: Path) -> None:
    store = CaseStore(tmp_path / "cases.sqlite")
    result = handle_outcome_click(
        store,
        custom_id="soc:benign:0",
        user=SimpleNamespace(name="x", id=1),
    )
    assert result["ok"] is False
    assert "must be >= 1" in result["error"]


def test_handle_outcome_click_resolves(tmp_path: Path) -> None:
    db = tmp_path / "cases.sqlite"
    store = CaseStore(db)
    opened = store.open_case(
        title="Discord click",
        alert_id="alert-discord-1",
        agent_name="pop-os-native",
        summary="lab",
        severity="medium",
        recommended_action="document",
    )
    case_id = int(opened["id"])
    user = SimpleNamespace(name="alice", id=4242)
    result = handle_outcome_click(
        store,
        custom_id=outcome_custom_id(BENIGN, case_id),
        user=user,
    )
    assert result["ok"] is True
    assert result["disposition"] == BENIGN
    case = store.get_case(case_id)
    assert case["status"] == BENIGN
    assert case["analyst_disposition"] == BENIGN
    assert any("closed from Discord by alice" in (n.get("note") or "") for n in case["notes"])
    assert any((n.get("author") or "").startswith("discord:alice") for n in case["notes"])


def test_handle_outcome_click_already_closed(tmp_path: Path) -> None:
    db = tmp_path / "cases.sqlite"
    store = CaseStore(db)
    opened = store.open_case(
        title="Closed",
        alert_id="alert-discord-2",
        agent_name="pop",
        summary="lab",
    )
    case_id = int(opened["id"])
    store.resolve_proposal(case_id, disposition=FALSE_POSITIVE, note="first", author="human")
    result = handle_outcome_click(
        store,
        custom_id=outcome_custom_id(CONFIRMED_COMPROMISE, case_id),
        user=SimpleNamespace(name="bob", id=1),
    )
    assert result["ok"] is False
    assert "already closed" in result["error"]
    assert store.get_case(case_id)["status"] == FALSE_POSITIVE


def test_handle_outcome_click_missing_case(tmp_path: Path) -> None:
    store = CaseStore(tmp_path / "cases.sqlite")
    result = handle_outcome_click(
        store,
        custom_id="soc:benign:99999",
        user=SimpleNamespace(name="x", id=1),
    )
    assert result["ok"] is False
    assert "not found" in result["error"]


def test_interaction_allowed_channel_and_guild() -> None:
    settings = Settings(discord_channel_id="111", discord_guild_id="222")
    ok, _ = interaction_allowed(settings, guild_id=222, channel_id=111)
    assert ok is True
    ok, reason = interaction_allowed(settings, guild_id=222, channel_id=999)
    assert ok is False
    assert "channel" in reason
    ok, reason = interaction_allowed(settings, guild_id=1, channel_id=111)
    assert ok is False
    assert "guild" in reason
