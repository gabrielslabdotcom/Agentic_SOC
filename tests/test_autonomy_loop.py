"""Helpers for autonomy_loop stop + timestamp cursor."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "autonomy_loop",
    _ROOT / "scripts" / "autonomy_loop.py",
)
assert _SPEC and _SPEC.loader
autonomy_loop = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(autonomy_loop)


def test_max_alert_timestamp() -> None:
    alerts = [
        {"timestamp": "2026-09-08T12:00:00.000Z"},
        {"timestamp": "2026-09-08T12:05:00.000Z"},
        {"timestamp": ""},
    ]
    assert autonomy_loop.max_alert_timestamp(alerts) == "2026-09-08T12:05:00.000Z"
    assert autonomy_loop.max_alert_timestamp([]) is None


def test_stop_requested_reads_event() -> None:
    autonomy_loop._STOP.clear()
    assert autonomy_loop.stop_requested() is False
    autonomy_loop._STOP.set()
    assert autonomy_loop.stop_requested() is True
    autonomy_loop._STOP.clear()
