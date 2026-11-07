"""Anthropic Messages API client for Ask Pop search (tool use).

Uses httpx only — no Anthropic SDK. Independent of the meaning-note LLM path.
"""

from __future__ import annotations

from typing import Any, Optional

import httpx

ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_BASE_URL = "https://api.anthropic.com"
DEFAULT_MODEL = "claude-haiku-4-5"


def extract_text(payload: dict[str, Any]) -> str:
    """Join text blocks from a Messages API response."""
    content = payload.get("content") if isinstance(payload, dict) else None
    if not isinstance(content, list):
        return ""
    parts: list[str] = []
    for block in content:
        if isinstance(block, dict) and block.get("type") == "text":
            text = block.get("text")
            if isinstance(text, str) and text.strip():
                parts.append(text.strip())
    return "\n".join(parts).strip()


def extract_tool_uses(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Return tool_use blocks as ``{id, name, input}``."""
    content = payload.get("content") if isinstance(payload, dict) else None
    if not isinstance(content, list):
        return []
    uses: list[dict[str, Any]] = []
    for block in content:
        if not isinstance(block, dict) or block.get("type") != "tool_use":
            continue
        tool_id = str(block.get("id") or "")
        name = str(block.get("name") or "")
        raw_input = block.get("input")
        args = raw_input if isinstance(raw_input, dict) else {}
        if tool_id and name:
            uses.append({"id": tool_id, "name": name, "input": args})
    return uses


async def complete_messages(
    *,
    base_url: str,
    api_key: str,
    model: str,
    messages: list[dict[str, Any]],
    system: Optional[str] = None,
    tools: Optional[list[dict[str, Any]]] = None,
    max_tokens: int = 1024,
    temperature: float = 0,
) -> dict[str, Any]:
    """POST ``/v1/messages`` and return the JSON body."""
    root = (base_url or DEFAULT_BASE_URL).rstrip("/")
    url = f"{root}/v1/messages"
    headers = {
        "x-api-key": api_key,
        "anthropic-version": ANTHROPIC_VERSION,
        "content-type": "application/json",
    }
    body: dict[str, Any] = {
        "model": (model or DEFAULT_MODEL).strip() or DEFAULT_MODEL,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    if system:
        body["system"] = system
    if tools:
        body["tools"] = tools
    async with httpx.AsyncClient(timeout=90) as client:
        resp = await client.post(url, headers=headers, json=body)
        resp.raise_for_status()
        payload = resp.json()
    if not isinstance(payload, dict):
        return {}
    return payload
