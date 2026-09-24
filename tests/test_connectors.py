"""Connector store, setup token, and settings merge."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentic_soc import api as api_mod
from agentic_soc.config import Settings, get_settings
from agentic_soc.connectors import ensure_setup_token, public_catalog, save_connector


@pytest.fixture()
def data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("AGENTIC_SOC_DATA", str(tmp_path))
    monkeypatch.delenv("AGENTIC_SOC_APPLIANCE", raising=False)
    return tmp_path


def test_absent_store_matches_env_settings(data_dir: Path) -> None:
    merged = get_settings()
    plain = Settings()
    assert merged.wazuh_api_url == plain.wazuh_api_url
    assert merged.wazuh_api_password == plain.wazuh_api_password
    assert merged.cursor_api_key == plain.cursor_api_key


def test_appliance_without_store_blanks_lab_host(data_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTIC_SOC_APPLIANCE", "1")
    settings = get_settings()
    assert settings.wazuh_api_url == ""
    assert settings.wazuh_indexer_url == ""
    assert settings.wazuh_api_password == ""
    assert "192.168.50.254" not in settings.wazuh_dashboard_url


def test_store_overrides_env(data_dir: Path) -> None:
    token, _created = ensure_setup_token()
    save_connector(
        "wazuh",
        enabled=True,
        config={
            "wazuh_api_url": "https://siem.example:55000",
            "wazuh_api_user": "wazuh-wui",
            "wazuh_api_password": "store-secret",
            "wazuh_indexer_url": "https://siem.example:9200",
            "wazuh_indexer_user": "admin",
            "wazuh_indexer_password": "indexer-secret",
            "wazuh_dashboard_url": "https://siem.example",
        },
    )
    settings = get_settings()
    assert settings.wazuh_api_url == "https://siem.example:55000"
    assert settings.wazuh_api_password == "store-secret"
    assert token


def test_public_catalog_masks_secrets(data_dir: Path) -> None:
    save_connector(
        "wazuh",
        enabled=True,
        config={
            "wazuh_api_url": "https://siem.example:55000",
            "wazuh_api_password": "super-secret-value",
            "wazuh_indexer_url": "https://siem.example:9200",
            "wazuh_indexer_password": "indexer-secret-value",
        },
    )
    body = public_catalog()
    text = str(body)
    assert "super-secret-value" not in text
    assert "indexer-secret-value" not in text
    wazuh = next(card for card in body["connectors"] if card["id"] == "wazuh")
    password = next(field for field in wazuh["fields"] if field["key"] == "wazuh_api_password")
    assert password["hint"] == "••••alue"
    assert password["configured"] is True
    assert "value" not in password


def test_second_llm_disables_the_first(data_dir: Path) -> None:
    save_connector(
        "cursor",
        enabled=True,
        config={"cursor_api_key": "cursor-key-1234", "cursor_agent_model": "composer-2.5"},
    )
    save_connector(
        "openai",
        enabled=True,
        config={
            "openai_base_url": "https://api.openai.com/v1",
            "openai_api_key": "sk-test-9999",
            "openai_model": "gpt-4o-mini",
        },
    )
    body = public_catalog()
    by_id = {card["id"]: card for card in body["connectors"]}
    assert by_id["openai"]["enabled"] is True
    assert by_id["cursor"]["enabled"] is False
    settings = get_settings()
    assert settings.llm_connector == "openai"
    assert settings.openai_api_key == "sk-test-9999"
    assert settings.cursor_api_key == ""
    assert settings.autonomy_cursor_agent is False


def test_blank_secret_keeps_stored_value(data_dir: Path) -> None:
    save_connector(
        "virustotal",
        enabled=True,
        config={"virustotal_api_key": "vt-secret-key"},
    )
    save_connector("virustotal", enabled=True, config={"virustotal_api_key": ""})
    assert get_settings().virustotal_api_key == "vt-secret-key"


def test_setup_ready_and_token(data_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTIC_SOC_APPLIANCE", "1")
    client = TestClient(api_mod.app)
    before = client.get("/tools/setup")
    assert before.status_code == 200
    assert before.json()["ready"] is False

    denied = client.put(
        "/tools/connectors/wazuh",
        json={
            "enabled": True,
            "config": {
                "wazuh_api_url": "https://siem.example:55000",
                "wazuh_indexer_url": "https://siem.example:9200",
            },
        },
    )
    assert denied.status_code == 401

    token, _created = ensure_setup_token()
    saved = client.put(
        "/tools/connectors/wazuh",
        headers={"X-Setup-Token": token},
        json={
            "enabled": True,
            "config": {
                "wazuh_api_url": "https://siem.example:55000",
                "wazuh_indexer_url": "https://siem.example:9200",
                "wazuh_api_password": "pw",
                "wazuh_indexer_password": "pw2",
            },
        },
    )
    assert saved.status_code == 200
    assert "pw2" not in saved.text
    after = client.get("/tools/setup")
    assert after.json()["ready"] is True

    dash = client.get("/dashboard/")
    assert dash.status_code == 200
    assert "host.docker.internal" in dash.text
    assert "Connectors" in dash.text
