"""Tests for Cursor cloud investigation hook (mocked SDK / dry-run)."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from agentic_soc.config import Settings
from agentic_soc.cursor_agent import (
    build_investigation_prompt,
    cursor_agent_enabled,
    kick_cursor_investigation,
    maybe_kick_after_case_open,
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


def test_build_prompt_includes_case_fields_and_propose_only():
    prompt = build_investigation_prompt(
        _case(),
        api_url="http://127.0.0.1:8080",
    )
    assert "case_id: 42" in prompt
    assert "alert_id: abc-123" in prompt
    assert "investigate_and_document" in prompt
    assert "Propose only" in prompt
    assert "Never execute containment" in prompt or "never" in prompt.lower()
    assert "PATCH" in prompt
    assert "/tools/update_case/42" in prompt
    assert "203.0.113.9" in prompt


def test_build_prompt_without_api_url_asks_for_paste():
    prompt = build_investigation_prompt(_case(), api_url="")
    assert "AGENTIC_SOC_API_URL` is not set" in prompt or "not set" in prompt
    assert "paste" in prompt.lower()


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
    assert "case_id: 42" in out["prompt"]
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


def test_run_cloud_prompt_mocked_sdk():
    settings = Settings(
        cursor_api_key="cursor_test_key",
        cursor_agent_model="composer-2.5",
        cursor_agent_repo="https://github.com/example/Agentic_SOC",
        cursor_agent_starting_ref="main",
        agentic_soc_api_url="http://127.0.0.1:8080",
        wazuh_api_password="x",
        wazuh_indexer_password="x",
    )

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
        # Re-import path uses deferred import inside _run_cloud_prompt
        out = kick_cursor_investigation(_case(), settings=settings, wait=True)

    assert out["ok"] is True
    assert out["waited"] is True
    mock_agent.prompt.assert_called_once()


def test_sdk_startup_error_fail_soft():
    settings = Settings(
        cursor_api_key="cursor_test_key",
        cursor_agent_repo="https://github.com/example/Agentic_SOC",
        wazuh_api_password="x",
        wazuh_indexer_password="x",
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
