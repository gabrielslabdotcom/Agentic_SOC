"""OpenAI-compatible meaning note from a mocked chat response."""

from __future__ import annotations

import asyncio

import pytest

from agentic_soc.config import Settings
from agentic_soc.openai_llm import draft_meaning_note, meaning_note_from_reply


def test_meaning_note_shape() -> None:
    note = meaning_note_from_reply(
        "What it means\nport scan\n\nEvidence\nSRC=198.51.100.10\n\n"
        "Related cases\nnone\n\nNext steps\n1. ask a human\n",
        model="gpt-test",
    )
    assert "containment=not_executed" in note
    assert "What it means" in note
    assert "Evidence" in note
    assert "Related cases" in note
    assert "Next steps" in note
    assert "model=gpt-test" in note


def test_draft_meaning_note_from_mocked_http(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {
                "choices": [
                    {
                        "message": {
                            "content": (
                                "What it means\nnoise\n\nEvidence\nrule 100102\n\n"
                                "Related cases\n#4\n\nNext steps\n1. review\n"
                            )
                        }
                    }
                ]
            }

    class _Client:
        def __init__(self, *args: object, **kwargs: object) -> None:
            self.posts: list[str] = []

        async def __aenter__(self) -> _Client:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def post(self, url: str, **kwargs: object) -> _Response:
            self.posts.append(url)
            return _Response()

    monkeypatch.setattr("agentic_soc.openai_llm.httpx.AsyncClient", _Client)
    settings = Settings(
        openai_base_url="https://llm.example/v1",
        openai_api_key="sk-test",
        openai_model="local-model",
    )
    drafted = asyncio.run(draft_meaning_note(settings, {"case_id": 9, "title": "scan"}))
    assert drafted["ok"] is True
    note = drafted["note"]
    assert "containment=not_executed" in note
    assert "What it means" in note
    assert "Evidence" in note
    assert "Related cases" in note
    assert "Next steps" in note
    assert "model=local-model" in note
    assert "sk-test" not in note
