"""Analyst UI instance detection."""

from pathlib import Path

from agentic_soc.config import Settings


def test_default_instance_is_mac_local(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("AGENTIC_SOC_INSTANCE", raising=False)
    settings = Settings(cases_db_path=str(tmp_path / "cases.sqlite"), agentic_soc_instance="")
    assert settings.resolve_instance() == "mac-local"


def test_pop_path_detects_live(monkeypatch) -> None:
    monkeypatch.delenv("AGENTIC_SOC_INSTANCE", raising=False)
    settings = Settings(
        cases_db_path="/home/admin/Agentic_SOC/data/cases.sqlite",
        agentic_soc_instance="",
    )
    assert settings.resolve_instance() == "pop-live"


def test_explicit_instance_wins(tmp_path: Path) -> None:
    settings = Settings(
        cases_db_path=str(tmp_path / "cases.sqlite"),
        agentic_soc_instance="pop-live",
    )
    assert settings.resolve_instance() == "pop-live"
