"""OpenAI-compatible chat client for the incident meaning note.

The model sees the same read-only packet as the Cursor hook. The reply is
copied onto the incident. Containment is never requested.
"""

from __future__ import annotations

import json
from typing import Any, Optional

import httpx

from agentic_soc.config import Settings

OPENAI_AUTHOR = "openai_compatible"
NOTE_PREFIX = "[llm_investigation]"
MAX_NOTE_CHARS = 50000


def meaning_note_from_reply(reply: str, *, model: str) -> str:
    """Shape a chat reply into the incident note analysts already read."""
    body = (reply or "").strip() or "(model returned an empty reply)"
    if len(body) > MAX_NOTE_CHARS:
        body = body[: MAX_NOTE_CHARS - 1] + "…"
    model_name = (model or "").strip() or "openai"
    return (
        f"{NOTE_PREFIX}\n"
        "provider=openai\n"
        f"model={model_name}\n"
        "containment=not_executed\n\n"
        f"{body}"
    )


def parse_chat_content(payload: dict[str, Any]) -> str:
    choices = payload.get("choices") if isinstance(payload, dict) else None
    if not isinstance(choices, list) or not choices:
        return ""
    message = choices[0].get("message") if isinstance(choices[0], dict) else None
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    if isinstance(content, str):
        return content.strip()
    return ""


async def complete_chat(
    *,
    base_url: str,
    api_key: str,
    model: str,
    messages: list[dict[str, str]],
    max_tokens: int = 800,
) -> str:
    url = base_url.rstrip("/") + "/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    body = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": 0,
    }
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(url, headers=headers, json=body)
        resp.raise_for_status()
        payload = resp.json()
    if not isinstance(payload, dict):
        return ""
    return parse_chat_content(payload)


async def draft_meaning_note(settings: Settings, packet: dict[str, Any]) -> dict[str, Any]:
    """Call the chat endpoint and return a meaning note. Does not write the case."""
    base = (settings.openai_base_url or "").strip() or "https://api.openai.com/v1"
    key = (settings.openai_api_key or "").strip()
    model = (settings.openai_model or "").strip() or "gpt-4o-mini"
    if not key:
        return {"ok": False, "skipped": True, "reason": "no_api_key", "error": "API key is empty"}
    packet_text = json.dumps(packet, default=str)[:6000]
    case_id = packet.get("case_id")
    messages = [
        {
            "role": "user",
            "content": (
                "You are an Agentic SOC investigation assistant.\n"
                "Propose only. Never execute containment.\n"
                "Use only the packet below.\n\n"
                f"Incident packet:\n{packet_text}\n\n"
                f"Write the note for incident #{case_id} with these headings:\n"
                "What it means\nEvidence\nRelated cases\nNext steps\n"
                "State that containment stays manual."
            ),
        }
    ]
    try:
        reply = await complete_chat(
            base_url=base,
            api_key=key,
            model=model,
            messages=messages,
        )
    except httpx.HTTPError as exc:
        return {"ok": False, "error": str(exc), "provider": "openai"}
    note = meaning_note_from_reply(reply, model=model)
    return {
        "ok": True,
        "provider": "openai",
        "model": model,
        "reply": reply,
        "note": note,
    }


def persist_openai_note(
    case_id: Any,
    note: str,
    *,
    settings: Optional[Settings] = None,
) -> dict[str, Any]:
    if case_id is None or case_id == "":
        return {"ok": False, "error": "no case_id"}
    try:
        cid = int(case_id)
    except (TypeError, ValueError):
        return {"ok": False, "error": f"invalid case_id={case_id!r}"}
    from agentic_soc.tools import SocTools

    tools = SocTools(settings=settings)
    updated = tools.update_case(cid, note=note, author=OPENAI_AUTHOR)
    if updated.get("error"):
        return {"ok": False, "error": updated.get("error"), "case_id": cid}
    return {"ok": True, "case_id": cid, "note_chars": len(note), "author": OPENAI_AUTHOR}
