"""Tests for Cursor cloud investigation hook (mocked SDK / dry-run)."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from agentic_soc.cases import CaseStore
from agentic_soc.config import Settings
from agentic_soc.cursor_agent import (
    INVESTIGATION_AUTHOR,
    build_investigation_prompt,
    cursor_agent_enabled,
    kick_cursor_investigation,
    maybe_kick_after_case_open,
    persist_investigation_note,
    extract_result_text,
)


def _case(**overrides: object) -> dict:
    base = {
        "id": 42,
        "title": "[auto][suspicious] SSH auth failure",
        "disposition": "suspicious",
        "severity": "high",
        "confidence": 0.7,
        "alert_id": "abc-123",
        "agent_name": "pop-os-native",
        "rule_id": "5710",
        "rule_level": 10,
        "timestamp": "2026-09-07T15:00:00.000Z",
        "recommended_action": "investigate_and_document",
        "reasons": ["auth failure cluster", "non-lab source"],
        "description": "sshd: authentication failed",
        "full_log": "Failed password for root from 203.0.113.9",
        "iocs": [{"ioc": "203.0.113.9", "ioc_type": "ip"}],
        "enrichments": [{"ioc": "203.0.113.9", "malicious": 2, "suspicious": 1}],
    }
    base.update(overrides)
    return base


def _settings(tmp_path, **kwargs: object) -> Settings:
    base = dict(
        cases_db_path=str(tmp_path / "cases.sqlite"),
        discord_webhook_url="",
        wazuh_api_password="x",
        wazuh_indexer_password="x",
    )
    base.update(kwargs)
    return Settings(**base)  # type: ignore[arg-type]


def test_build_prompt_includes_case_fields_and_propose_only():
    packet = {
        "case_id": 42,
        "brief": {"headline": "sshd auth failure", "do_next": ["Confirm.", "Close.", "Suppress."]},
        "related_case_ids": [7],
        "trigger_alert": {"id": "abc-123", "evidence": "Failed password for root"},
    }
    prompt = build_investigation_prompt(_case(incident_packet=packet), api_url="http://127.0.0.1:8080", packet=packet)
    assert "42" in prompt
    assert "Propose only" in prompt
    assert "Never execute containment" in prompt
    assert "Do **not** approve" in prompt
    assert "Do **not** call Wazuh" in prompt
    assert "/tools/update_case" not in prompt
    assert "192.168.50.254" not in prompt
    assert "related_case_ids" in prompt
    assert "sshd auth failure" in prompt


def test_build_prompt_without_api_url_auto_copy():
    prompt = build_investigation_prompt(_case(), api_url="")
    assert "final reply" in prompt.lower()
    assert "192.168.50.254" not in prompt
    assert "approve" in prompt.lower()
    assert "Do **not** call Wazuh" in prompt


def test_cursor_agent_enabled_defaults_false(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("AUTONOMY_CURSOR_AGENT", raising=False)
    monkeypatch.delenv("CURSOR_API_KEY", raising=False)
    settings = Settings(
        autonomy_cursor_agent=False,
        cursor_api_key="",
        wazuh_api_password="x",
        wazuh_indexer_password="x",
    )
    assert cursor_agent_enabled(settings) is False


def test_cursor_agent_enabled_requires_key(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AUTONOMY_CURSOR_AGENT", "true")
    monkeypatch.delenv("CURSOR_API_KEY", raising=False)
    settings = Settings(
        autonomy_cursor_agent=True,
        cursor_api_key="",
        wazuh_api_password="x",
        wazuh_indexer_password="x",
    )
    assert cursor_agent_enabled(settings) is False


def test_cursor_agent_enabled_true(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AUTONOMY_CURSOR_AGENT", "true")
    settings = Settings(
        autonomy_cursor_agent=True,
        cursor_api_key="cursor_test_key",
        wazuh_api_password="x",
        wazuh_indexer_password="x",
    )
    assert cursor_agent_enabled(settings) is True


def test_dry_run_returns_prompt_without_sdk():
    settings = Settings(
        cursor_api_key="cursor_test_key",
        cursor_agent_repo="https://github.com/example/Agentic_SOC",
        agentic_soc_api_url="http://127.0.0.1:8080",
        wazuh_api_password="x",
        wazuh_indexer_password="x",
    )
    out = kick_cursor_investigation(_case(), settings=settings, dry_run=True)
    assert out["ok"] is True
    assert out["dry_run"] is True
    assert "42" in out["prompt"]
    assert "Do **not** call Wazuh" in out["prompt"]
    assert out["repo_url"] == "https://github.com/example/Agentic_SOC"


def test_maybe_kick_skipped_when_disabled(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AUTONOMY_CURSOR_AGENT", "false")
    settings = Settings(
        autonomy_cursor_agent=False,
        cursor_api_key="cursor_test_key",
        wazuh_api_password="x",
        wazuh_indexer_password="x",
    )
    out = maybe_kick_after_case_open(_case(), settings=settings)
    assert out.get("skipped") is True


def test_persist_investigation_note(tmp_path) -> None:
    settings = _settings(tmp_path)
    store = CaseStore(settings.cases_path)
    opened = store.open_case(title="port scan")
    out = persist_investigation_note(
        opened["id"],
        "lab nmap from Kali; document only",
        outcome={"status": "finished", "run_id": "run-1", "agent_id": "bc-abc"},
        settings=settings,
    )
    assert out["ok"] is True
    got = store.get_case(opened["id"])
    last = got["notes"][-1]
    assert last["author"] == INVESTIGATION_AUTHOR
    assert "[cursor_investigation]" in last["note"]
    assert "lab nmap from Kali" in last["note"]
    assert "containment=not_executed" in last["note"]


def test_extract_result_text() -> None:
    assert extract_result_text(SimpleNamespace(result="  hello  ")) == "hello"
    assert extract_result_text(None) == ""
    assert extract_result_text("plain") == "plain"


def test_notify_investigation_ready_embed() -> None:
    import asyncio
    from unittest.mock import AsyncMock

    from agentic_soc.discord_notify import DiscordNotifier

    settings = Settings(
        discord_webhook_url="https://example.invalid/hook",
        wazuh_api_password="x",
        wazuh_indexer_password="x",
    )
    notifier = DiscordNotifier(settings)
    mock_send = AsyncMock(return_value={"ok": True})
    with patch.object(notifier, "send_raw", mock_send):
        asyncio.run(
            notifier.notify_investigation_ready(
                {"id": 7, "title": "scan", "disposition": "suspicious", "severity": "high"},
                note="[cursor_investigation]\nstatus=finished\n\nLooks like lab nmap.",
                outcome={"run_id": "run-9"},
            )
        )
    mock_send.assert_awaited_once()
    kwargs = mock_send.await_args.kwargs
    assert "case #7" in kwargs["content"]
    embed = kwargs["embeds"][0]
    assert "Investigation note ready #7" in embed["title"]
    fields = {f["name"]: f["value"] for f in embed["fields"]}
    assert "lab nmap" in fields["Note preview"]
    assert "containment" in fields["Next"].lower()

def test_run_cloud_prompt_mocked_sdk(tmp_path):
    settings = _settings(
        tmp_path,
        cursor_api_key="cursor_test_key",
        cursor_agent_model="composer-2.5",
        cursor_agent_repo="https://github.com/example/Agentic_SOC",
        cursor_agent_starting_ref="main",
        agentic_soc_api_url="http://127.0.0.1:8080",
    )
    opened = CaseStore(settings.cases_path).open_case(title="ssh fail")

    fake_result = SimpleNamespace(
        status="finished",
        id="run-1",
        agent_id="bc-abc",
        result="Investigation note: lab noise",
    )

    mock_agent = MagicMock()
    mock_agent.prompt.return_value = fake_result
    mock_opts = MagicMock()
    mock_cloud = MagicMock()
    mock_repo = MagicMock()

    with patch.dict(
        "sys.modules",
        {
            "cursor_sdk": MagicMock(
                Agent=mock_agent,
                AgentOptions=mock_opts,
                CloudAgentOptions=mock_cloud,
                CloudRepository=mock_repo,
                CursorAgentError=type("CursorAgentError", (Exception,), {"message": "", "is_retryable": False}),
            )
        },
    ):
        out = kick_cursor_investigation(
            _case(id=opened["id"]),
            settings=settings,
            wait=True,
        )

    assert out["ok"] is True
    assert out["waited"] is True
    assert out.get("persisted") is True
    mock_agent.prompt.assert_called_once()
    notes = CaseStore(settings.cases_path).get_case(opened["id"])["notes"]
    assert any("lab noise" in (n.get("note") or "") for n in notes)


def test_sdk_startup_error_fail_soft(tmp_path):
    settings = _settings(
        tmp_path,
        cursor_api_key="cursor_test_key",
        cursor_agent_repo="https://github.com/example/Agentic_SOC",
    )

    class Boom(Exception):
        message = "auth failed"
        is_retryable = False

    mock_agent = MagicMock()
    mock_agent.prompt.side_effect = Boom("auth failed")

    with patch.dict(
        "sys.modules",
        {
            "cursor_sdk": MagicMock(
                Agent=mock_agent,
                AgentOptions=MagicMock(),
                CloudAgentOptions=MagicMock(),
                CloudRepository=MagicMock(),
                CursorAgentError=Boom,
            )
        },
    ):
        out = kick_cursor_investigation(_case(), settings=settings, wait=True)

    assert out["ok"] is False
    assert out["waited"] is True
    assert "auth failed" in str(out.get("error") or "")


def test_scm_access_error_retries_norepo(tmp_path):
    settings = _settings(
        tmp_path,
        cursor_api_key="cursor_test_key",
        cursor_agent_repo="https://github.com/example/Agentic_SOC",
        cursor_agent_norepo_fallback=True,
    )
    opened = CaseStore(settings.cases_path).open_case(title="scm")

    class ScmErr(Exception):
        message = (
            "[validation_error] The SCM integration does not have access to "
            "repository example/Agentic_SOC to verify branch existence."
        )
        is_retryable = False

    fake_result = SimpleNamespace(
        status="finished",
        id="run-2",
        agent_id="bc-def",
        result="no-repo ok",
    )
    mock_agent = MagicMock()
    mock_agent.prompt.side_effect = [ScmErr("scm"), fake_result]

    with patch.dict(
        "sys.modules",
        {
            "cursor_sdk": MagicMock(
                Agent=mock_agent,
                AgentOptions=MagicMock(),
                CloudAgentOptions=MagicMock(),
                CloudRepository=MagicMock(),
                CursorAgentError=ScmErr,
            )
        },
    ):
        out = kick_cursor_investigation(
            _case(id=opened["id"]),
            settings=settings,
            wait=True,
        )

    assert out["ok"] is True
    assert mock_agent.prompt.call_count == 2
    assert out.get("persisted") is True


def test_maybe_kick_never_raises(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AUTONOMY_CURSOR_AGENT", "true")
    settings = Settings(
        autonomy_cursor_agent=True,
        cursor_api_key="cursor_test_key",
        wazuh_api_password="x",
        wazuh_indexer_password="x",
    )
    with patch(
        "agentic_soc.cursor_agent.kick_cursor_investigation",
        side_effect=RuntimeError("boom"),
    ):
        out = maybe_kick_after_case_open(_case(), settings=settings, enabled=True)
    assert out["ok"] is False
    assert "boom" in out["error"]
