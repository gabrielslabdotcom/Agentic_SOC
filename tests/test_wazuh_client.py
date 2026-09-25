"""Wazuh client active-response request shape (no live manager)."""

from __future__ import annotations

import asyncio

import httpx

from agentic_soc.config import Settings
from agentic_soc.wazuh_client import WazuhClient


class _Response:
    def __init__(self, *, status_code: int = 200, payload: dict | None = None, text: str = "") -> None:
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            request = httpx.Request("GET", "https://wazuh.example")
            raise httpx.HTTPStatusError("error", request=request, response=httpx.Response(self.status_code))

    def json(self) -> dict:
        return self._payload


def test_resolve_agent_and_active_response_shape(monkeypatch) -> None:
    calls: list[tuple] = []

    class _Client:
        def __init__(self, *args, **kwargs) -> None:
            del args, kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args) -> bool:
            return False

        async def post(self, url, **kwargs):
            calls.append(("POST", url))
            return _Response(text='"test-token"')

        async def get(self, url, **kwargs):
            params = kwargs.get("params") or {}
            calls.append(("GET", url, params))
            if url.endswith("/agents"):
                return _Response(
                    payload={
                        "data": {
                            "affected_items": [
                                {
                                    "id": "005",
                                    "name": "lab-linux",
                                    "ip": "203.0.113.5",
                                    "status": "active",
                                    "os": {"name": "Ubuntu", "platform": "ubuntu"},
                                },
                                {
                                    "id": "006",
                                    "name": "other",
                                    "ip": "203.0.113.6",
                                    "status": "disconnected",
                                    "os": {"name": "Ubuntu", "platform": "ubuntu"},
                                },
                            ]
                        }
                    }
                )
            if url.endswith("/active-response"):
                return _Response(payload={"data": {"affected_items": [{"name": "network-isolation"}]}})
            return _Response(payload={})

        async def put(self, url, **kwargs):
            calls.append(("PUT", url, kwargs.get("params"), kwargs.get("json")))
            return _Response(
                payload={"error": 0, "data": {"affected_items": ["005"], "failed_items": []}}
            )

    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    client = WazuhClient(
        Settings(
            wazuh_api_url="https://wazuh.example:55000",
            wazuh_api_user="user",
            wazuh_api_password="pw",
            wazuh_api_verify_ssl=False,
        )
    )

    async def _run():
        found = await client.resolve_agent_by_name("lab-linux")
        missing = await client.resolve_agent_by_name("not-here")
        listed = await client.list_active_response_commands()
        sent = await client.active_response(["005"], "network-isolation")
        return found, missing, listed, sent

    found, missing, listed, sent = asyncio.run(_run())
    assert found["ok"] is True
    assert found["agent"]["id"] == "005"
    assert found["agent"]["platform"] == "ubuntu"
    assert missing["ok"] is False
    assert missing["error"] == "agent_not_found"
    assert listed["data"]["affected_items"][0]["name"] == "network-isolation"
    assert sent["error"] == 0
    put = [item for item in calls if item[0] == "PUT"][-1]
    assert put[2] == {"agents_list": "005"}
    assert put[3] == {"command": "network-isolation"}


def test_resolve_ambiguous_name(monkeypatch) -> None:
    class _Client:
        def __init__(self, *args, **kwargs) -> None:
            del args, kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args) -> bool:
            return False

        async def post(self, url, **kwargs):
            return _Response(text='"test-token"')

        async def get(self, url, **kwargs):
            return _Response(
                payload={
                    "data": {
                        "affected_items": [
                            {"id": "001", "name": "dup", "status": "active", "ip": "203.0.113.1", "os": {}},
                            {"id": "002", "name": "dup", "status": "active", "ip": "203.0.113.2", "os": {}},
                        ]
                    }
                }
            )

        async def put(self, url, **kwargs):
            raise AssertionError("ambiguous resolve must not send active response")

    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    client = WazuhClient(
        Settings(
            wazuh_api_url="https://wazuh.example:55000",
            wazuh_api_user="user",
            wazuh_api_password="pw",
        )
    )
    found = asyncio.run(client.resolve_agent_by_name("dup"))
    assert found["ok"] is False
    assert found["error"] == "agent_name_ambiguous"
    assert len(found["matches"]) == 2
