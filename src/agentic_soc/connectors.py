"""First-party connector catalog and on-disk config store.

The store lives next to the case database (or in ``AGENTIC_SOC_DATA``).
API responses never include secret values.
"""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Any, Optional

import httpx

from agentic_soc.config import Settings

_REPO_ROOT = Path(__file__).resolve().parents[2]

_BLANK_WAZUH: dict[str, Any] = {
    "wazuh_api_url": "",
    "wazuh_api_user": "",
    "wazuh_api_password": "",
    "wazuh_api_verify_ssl": False,
    "wazuh_indexer_url": "",
    "wazuh_indexer_user": "",
    "wazuh_indexer_password": "",
    "wazuh_indexer_verify_ssl": False,
    "wazuh_dashboard_url": "",
}

# key, label, secret, input kind (text | password | bool)
_FIELDS: dict[str, list[tuple[str, str, bool, str]]] = {
    "wazuh": [
        ("wazuh_api_url", "API URL", False, "text"),
        ("wazuh_api_user", "API user", False, "text"),
        ("wazuh_api_password", "API password", True, "password"),
        ("wazuh_api_verify_ssl", "Verify API TLS", False, "bool"),
        ("wazuh_indexer_url", "Indexer URL", False, "text"),
        ("wazuh_indexer_user", "Indexer user", False, "text"),
        ("wazuh_indexer_password", "Indexer password", True, "password"),
        ("wazuh_indexer_verify_ssl", "Verify indexer TLS", False, "bool"),
        ("wazuh_dashboard_url", "Dashboard URL", False, "text"),
    ],
    "cursor": [
        ("cursor_api_key", "API key", True, "password"),
        ("cursor_agent_model", "Model", False, "text"),
        ("cursor_agent_repo", "Repository URL", False, "text"),
        ("cursor_agent_starting_ref", "Starting ref", False, "text"),
    ],
    "openai": [
        ("openai_base_url", "Base URL", False, "text"),
        ("openai_api_key", "API key", True, "password"),
        ("openai_model", "Model", False, "text"),
    ],
    "virustotal": [
        ("virustotal_api_key", "API key", True, "password"),
    ],
    "discord": [
        ("discord_webhook_url", "Webhook URL", True, "password"),
        ("discord_bot_token", "Bot token", True, "password"),
        ("discord_channel_id", "Channel ID", False, "text"),
        ("discord_guild_id", "Guild ID", False, "text"),
    ],
}

CATALOG: list[dict[str, Any]] = [
    {
        "id": "wazuh",
        "kind": "siem",
        "name": "Wazuh",
        "blurb": "Manager API and indexer. Required before the queue polls.",
    },
    {
        "id": "cursor",
        "kind": "llm",
        "name": "Cursor",
        "blurb": "Cloud model writes the investigation note from the read-only packet.",
    },
    {
        "id": "openai",
        "kind": "llm",
        "name": "OpenAI-compatible",
        "blurb": "Chat endpoint for OpenAI, Ollama, or any compatible API.",
    },
    {
        "id": "virustotal",
        "kind": "enrichment",
        "name": "VirusTotal",
        "blurb": "IOC lookups on new incidents.",
    },
    {
        "id": "discord",
        "kind": "notify",
        "name": "Discord",
        "blurb": "Webhook for case pages. A bot token also starts the Gateway bot.",
    },
]

_LLM_IDS = ("cursor", "openai")
_DEFAULTS: dict[str, dict[str, Any]] = {
    "cursor": {"cursor_agent_model": "composer-2.5", "cursor_agent_starting_ref": "main"},
    "openai": {
        "openai_base_url": "https://api.openai.com/v1",
        "openai_model": "gpt-4o-mini",
    },
}


def appliance_mode() -> bool:
    return os.environ.get("AGENTIC_SOC_APPLIANCE", "").strip().lower() in ("1", "true", "yes")


def data_dir(settings: Optional[Settings] = None) -> Path:
    explicit = os.environ.get("AGENTIC_SOC_DATA", "").strip()
    if explicit:
        return Path(explicit)
    if settings is not None:
        return settings.cases_path.parent
    raw = os.environ.get("CASES_DB_PATH", "data/cases.sqlite")
    path = Path(raw)
    if not path.is_absolute():
        path = _REPO_ROOT / path
    return path.parent


def store_path(settings: Optional[Settings] = None) -> Path:
    return data_dir(settings) / "connectors.json"


def token_path(settings: Optional[Settings] = None) -> Path:
    return data_dir(settings) / "setup_token"


def _catalog_by_id() -> dict[str, dict[str, Any]]:
    return {item["id"]: item for item in CATALOG}


def known_connector(connector_id: str) -> bool:
    return connector_id in _catalog_by_id()


def _field_spec(connector_id: str) -> list[tuple[str, str, bool, str]]:
    return list(_FIELDS.get(connector_id) or [])


def _secret_keys(connector_id: str) -> set[str]:
    return {key for key, _label, secret, _kind in _field_spec(connector_id) if secret}


def _empty_config(connector_id: str) -> dict[str, Any]:
    config: dict[str, Any] = {}
    for key, _label, _secret, kind in _field_spec(connector_id):
        config[key] = False if kind == "bool" else ""
    config.update(_DEFAULTS.get(connector_id) or {})
    return config


def _coerce(connector_id: str, raw: dict[str, Any], previous: dict[str, Any]) -> dict[str, Any]:
    """Keep a blank secret so the console can save other fields without re-pasting it."""
    cleaned = _empty_config(connector_id)
    incoming = raw if isinstance(raw, dict) else {}
    for key, _label, secret, kind in _field_spec(connector_id):
        if key not in incoming:
            if secret:
                cleaned[key] = previous.get(key) or ""
            continue
        value = incoming.get(key)
        if kind == "bool":
            if isinstance(value, str):
                cleaned[key] = value.strip().lower() in ("1", "true", "yes", "on")
            else:
                cleaned[key] = bool(value)
            continue
        text = "" if value is None else str(value).strip()
        if secret and text == "":
            cleaned[key] = str(previous.get(key) or "")
        else:
            cleaned[key] = text
    return cleaned


def read_store(settings: Optional[Settings] = None) -> Optional[dict[str, Any]]:
    path = store_path(settings)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"connectors": {}}
    if not isinstance(data, dict):
        return {"connectors": {}}
    connectors = data.get("connectors")
    if not isinstance(connectors, dict):
        data["connectors"] = {}
    return data


def _write_store(data: dict[str, Any], settings: Optional[Settings] = None) -> None:
    path = store_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    blob = json.dumps(data, indent=2) + "\n"
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(blob, encoding="utf-8")
    try:
        tmp.chmod(0o600)
    except OSError:
        pass
    tmp.replace(path)
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _connectors(store: Optional[dict[str, Any]]) -> dict[str, Any]:
    if not store:
        return {}
    raw = store.get("connectors")
    return raw if isinstance(raw, dict) else {}


def _entry(store: Optional[dict[str, Any]], connector_id: str) -> dict[str, Any]:
    raw = _connectors(store).get(connector_id)
    if not isinstance(raw, dict):
        return {"enabled": False, "config": {}}
    config = raw.get("config") if isinstance(raw.get("config"), dict) else {}
    return {"enabled": bool(raw.get("enabled")), "config": config}


def mask_secret(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    if len(text) <= 4:
        return "••••"
    return "••••" + text[-4:]


def ensure_setup_token(settings: Optional[Settings] = None) -> tuple[str, bool]:
    """Return ``(token, created)``. The token is printed once by the appliance."""
    path = token_path(settings)
    if path.is_file():
        existing = path.read_text(encoding="utf-8").strip()
        if existing:
            return existing, False
    token = secrets.token_urlsafe(24)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(token + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return token, True


def token_matches(presented: Optional[str], settings: Optional[Settings] = None) -> bool:
    path = token_path(settings)
    if not path.is_file():
        return False
    expected = path.read_text(encoding="utf-8").strip()
    if not expected or presented is None:
        return False
    return secrets.compare_digest(expected, presented.strip())


def save_connector(
    connector_id: str,
    *,
    enabled: bool,
    config: dict[str, Any],
    settings: Optional[Settings] = None,
) -> dict[str, Any]:
    if not known_connector(connector_id):
        raise KeyError(connector_id)
    store = read_store(settings) or {"connectors": {}}
    connectors = _connectors(store)
    previous = _entry(store, connector_id)["config"]
    connectors[connector_id] = {
        "enabled": bool(enabled),
        "config": _coerce(connector_id, config, previous),
    }
    if enabled and connector_id in _LLM_IDS:
        for other in _LLM_IDS:
            if other == connector_id or other not in connectors:
                continue
            other_entry = connectors[other]
            if isinstance(other_entry, dict):
                other_entry["enabled"] = False
    store["connectors"] = connectors
    _write_store(store, settings)
    return public_catalog(settings)


def _configured(connector_id: str, config: dict[str, Any]) -> bool:
    if connector_id == "wazuh":
        return bool(str(config.get("wazuh_api_url") or "").strip()) and bool(
            str(config.get("wazuh_indexer_url") or "").strip()
        )
    if connector_id == "cursor":
        return bool(str(config.get("cursor_api_key") or "").strip())
    if connector_id == "openai":
        return bool(str(config.get("openai_api_key") or "").strip()) and bool(
            str(config.get("openai_base_url") or "").strip()
        )
    if connector_id == "virustotal":
        return bool(str(config.get("virustotal_api_key") or "").strip())
    if connector_id == "discord":
        return bool(str(config.get("discord_webhook_url") or "").strip()) or bool(
            str(config.get("discord_bot_token") or "").strip()
        )
    return False


def public_catalog(settings: Optional[Settings] = None) -> dict[str, Any]:
    store = read_store(settings)
    cards: list[dict[str, Any]] = []
    for item in CATALOG:
        cid = item["id"]
        entry = _entry(store, cid)
        config = entry["config"]
        fields: list[dict[str, Any]] = []
        for key, label, secret, kind in _field_spec(cid):
            raw = config.get(key, False if kind == "bool" else "")
            if kind == "bool":
                fields.append(
                    {"key": key, "label": label, "secret": False, "kind": "bool", "value": bool(raw)}
                )
            elif secret:
                text = str(raw or "")
                fields.append(
                    {
                        "key": key,
                        "label": label,
                        "secret": True,
                        "kind": "password",
                        "configured": bool(text.strip()),
                        "hint": mask_secret(text),
                    }
                )
            else:
                shown = str(raw or "")
                if shown == "" and key in (_DEFAULTS.get(cid) or {}):
                    shown = str(_DEFAULTS[cid][key])
                fields.append(
                    {"key": key, "label": label, "secret": False, "kind": kind, "value": shown}
                )
        cards.append(
            {
                **item,
                "enabled": bool(entry["enabled"]),
                "configured": _configured(cid, config),
                "fields": fields,
            }
        )
    return {"connectors": cards, "summary": summary(settings)}


def summary(settings: Optional[Settings] = None) -> dict[str, Any]:
    store = read_store(settings)
    wazuh = _entry(store, "wazuh")
    cursor = _entry(store, "cursor")
    openai = _entry(store, "openai")
    vt = _entry(store, "virustotal")
    discord = _entry(store, "discord")
    llm = ""
    if cursor["enabled"]:
        llm = "cursor"
    elif openai["enabled"]:
        llm = "openai"
    return {
        "ready": wazuh_ready(settings),
        "wazuh": bool(wazuh["enabled"] and _configured("wazuh", wazuh["config"])),
        "llm": llm,
        "virustotal": bool(vt["enabled"] and _configured("virustotal", vt["config"])),
        "discord": bool(discord["enabled"] and _configured("discord", discord["config"])),
    }


def configured_llm(settings: Optional[Settings] = None) -> Optional[str]:
    """Enabled LLM in the store. ``None`` when the store has no LLM choice."""
    store = read_store(settings)
    if store is None:
        return None
    cursor = _entry(store, "cursor")
    openai = _entry(store, "openai")
    if cursor["enabled"] and openai["enabled"]:
        return "cursor"
    if cursor["enabled"]:
        return "cursor"
    if openai["enabled"]:
        return "openai"
    if "cursor" in _connectors(store) or "openai" in _connectors(store):
        return ""
    return None


def discord_bot_enabled(settings: Optional[Settings] = None) -> bool:
    store = read_store(settings)
    entry = _entry(store, "discord")
    if not entry["enabled"]:
        return False
    return bool(str(entry["config"].get("discord_bot_token") or "").strip())


def wazuh_ready(settings: Optional[Settings] = None) -> bool:
    """True when the poller may talk to Wazuh.

    Appliance mode stays false until the wizard saves Wazuh, so an empty
    store cannot fall through to the lab host baked into Settings.
    """
    store = read_store(settings)
    entry = _entry(store, "wazuh")
    if entry["enabled"] and _configured("wazuh", entry["config"]):
        return True
    if store is not None and "wazuh" in _connectors(store):
        return False
    if appliance_mode():
        return False
    resolved = settings if settings is not None else None
    if resolved is None:
        return True
    return bool((resolved.wazuh_api_url or "").strip()) and bool(
        (resolved.wazuh_indexer_url or "").strip()
    )


def apply_store(settings: Settings) -> Settings:
    """Overlay the connector store. Absent store keeps ``.env`` and class defaults."""
    updates: dict[str, Any] = {}
    store = read_store(settings)
    saved = _entry(store, "wazuh")
    wazuh_saved = bool(saved["enabled"] and _configured("wazuh", saved["config"]))
    if appliance_mode() and not wazuh_saved:
        updates.update(_BLANK_WAZUH)

    if store is None:
        if not updates:
            return settings
        return settings.model_copy(update=updates)

    connectors = _connectors(store)
    if "wazuh" in connectors:
        entry = _entry(store, "wazuh")
        if entry["enabled"]:
            updates.update(_settings_from_config("wazuh", entry["config"]))
        else:
            updates.update(_BLANK_WAZUH)

    llm = configured_llm(settings)
    if llm == "cursor":
        updates.update(_settings_from_config("cursor", _entry(store, "cursor")["config"]))
        updates["autonomy_cursor_agent"] = True
        updates["llm_connector"] = "cursor"
        updates["openai_api_key"] = ""
    elif llm == "openai":
        updates.update(_settings_from_config("openai", _entry(store, "openai")["config"]))
        updates["autonomy_cursor_agent"] = False
        updates["cursor_api_key"] = ""
        updates["llm_connector"] = "openai"
    elif llm == "":
        updates["autonomy_cursor_agent"] = False
        updates["cursor_api_key"] = ""
        updates["openai_api_key"] = ""
        updates["llm_connector"] = ""

    if "virustotal" in connectors:
        entry = _entry(store, "virustotal")
        if entry["enabled"]:
            updates["virustotal_api_key"] = str(entry["config"].get("virustotal_api_key") or "")
        else:
            updates["virustotal_api_key"] = ""

    if "discord" in connectors:
        entry = _entry(store, "discord")
        if entry["enabled"]:
            updates.update(_settings_from_config("discord", entry["config"]))
        else:
            updates["discord_webhook_url"] = ""
            updates["discord_bot_token"] = ""
            updates["discord_channel_id"] = ""
            updates["discord_guild_id"] = ""

    if not updates:
        return settings
    return settings.model_copy(update=updates)


def _settings_from_config(connector_id: str, config: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, _label, _secret, kind in _field_spec(connector_id):
        if kind == "bool":
            out[key] = bool(config.get(key))
        else:
            out[key] = str(config.get(key) or "")
    return out


def _merged_config(connector_id: str, override: Optional[dict[str, Any]]) -> dict[str, Any]:
    entry = _entry(read_store(), connector_id)
    if override is None:
        return _coerce(connector_id, entry["config"], entry["config"])
    return _coerce(connector_id, override, entry["config"])


async def test_connector(
    connector_id: str,
    config: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    if not known_connector(connector_id):
        raise KeyError(connector_id)
    merged = _merged_config(connector_id, config)
    if connector_id == "wazuh":
        return await _test_wazuh(merged)
    if connector_id == "cursor":
        if str(merged.get("cursor_api_key") or "").strip():
            return {"ok": True, "message": "API key is set"}
        return {"ok": False, "error": "API key is empty"}
    if connector_id == "openai":
        return await _test_openai(merged)
    if connector_id == "virustotal":
        return await _test_virustotal(merged)
    if connector_id == "discord":
        return await _test_discord(merged)
    return {"ok": False, "error": "unknown connector"}


async def _test_wazuh(config: dict[str, Any]) -> dict[str, Any]:
    api_url = str(config.get("wazuh_api_url") or "").strip()
    indexer_url = str(config.get("wazuh_indexer_url") or "").strip()
    if not api_url or not indexer_url:
        return {"ok": False, "error": "API URL and indexer URL are required"}
    try:
        async with httpx.AsyncClient(verify=bool(config.get("wazuh_api_verify_ssl")), timeout=20) as client:
            resp = await client.post(
                f"{api_url.rstrip('/')}/security/user/authenticate?raw=true",
                auth=(
                    str(config.get("wazuh_api_user") or ""),
                    str(config.get("wazuh_api_password") or ""),
                ),
            )
            resp.raise_for_status()
        async with httpx.AsyncClient(
            verify=bool(config.get("wazuh_indexer_verify_ssl")), timeout=20
        ) as client:
            resp = await client.get(
                indexer_url.rstrip("/"),
                auth=(
                    str(config.get("wazuh_indexer_user") or ""),
                    str(config.get("wazuh_indexer_password") or ""),
                ),
            )
            resp.raise_for_status()
    except httpx.HTTPError as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "message": "Wazuh API and indexer accepted the credentials"}


async def _test_openai(config: dict[str, Any]) -> dict[str, Any]:
    from agentic_soc.openai_llm import complete_chat

    base = str(config.get("openai_base_url") or "").strip()
    key = str(config.get("openai_api_key") or "").strip()
    model = str(config.get("openai_model") or "gpt-4o-mini").strip()
    if not base or not key:
        return {"ok": False, "error": "Base URL and API key are required"}
    try:
        text = await complete_chat(
            base_url=base,
            api_key=key,
            model=model,
            messages=[{"role": "user", "content": "Reply with the single word ok."}],
            max_tokens=1,
        )
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}
    if not text:
        return {"ok": False, "error": "The endpoint returned an empty reply"}
    return {"ok": True, "message": "Chat endpoint replied"}


async def _test_virustotal(config: dict[str, Any]) -> dict[str, Any]:
    from agentic_soc.enrichment import VirusTotalClient

    key = str(config.get("virustotal_api_key") or "").strip()
    if not key:
        return {"ok": False, "error": "API key is empty"}
    settings = Settings(virustotal_api_key=key)
    result = await VirusTotalClient(settings).verify_auth()
    if result.get("ok"):
        return {"ok": True, "message": "VirusTotal accepted the API key"}
    return {"ok": False, "error": str(result.get("error") or "VirusTotal check failed")}


async def _test_discord(config: dict[str, Any]) -> dict[str, Any]:
    webhook = str(config.get("discord_webhook_url") or "").strip()
    token = str(config.get("discord_bot_token") or "").strip()
    if not webhook and not token:
        return {"ok": False, "error": "Set a webhook URL or a bot token"}
    messages: list[str] = []
    if webhook:
        if not (
            webhook.startswith("https://discord.com/api/webhooks/")
            or webhook.startswith("https://discordapp.com/api/webhooks/")
        ):
            return {"ok": False, "error": "Webhook URL is not a Discord webhook"}
        messages.append("webhook URL looks valid")
    if token:
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get(
                    "https://discord.com/api/v10/users/@me",
                    headers={"Authorization": f"Bot {token}"},
                )
                resp.raise_for_status()
        except httpx.HTTPError as exc:
            return {"ok": False, "error": str(exc)}
        messages.append("bot token accepted")
    return {"ok": True, "message": "; ".join(messages)}
