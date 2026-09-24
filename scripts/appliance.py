#!/usr/bin/env python3
"""Single-container supervisor: API, autonomy loop, and optional Discord bot.

The setup token is printed only when it is created (first boot of a data volume).
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from agentic_soc.connectors import discord_bot_enabled, ensure_setup_token  # noqa: E402
from agentic_soc.config import get_settings  # noqa: E402


def _python() -> str:
    return sys.executable


def _spawn(args: list[str]) -> subprocess.Popen[bytes]:
    return subprocess.Popen(args, cwd=str(_ROOT))


def _stop(proc: subprocess.Popen[bytes] | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


def _discord_signature() -> str:
    if not discord_bot_enabled():
        return ""
    settings = get_settings()
    token = (settings.discord_bot_token or "").strip()
    channel = (settings.discord_channel_id or "").strip()
    return f"{token}|{channel}"


def main() -> int:
    os.environ.setdefault("AGENTIC_SOC_APPLIANCE", "1")
    token, created = ensure_setup_token()
    if created:
        print(f"Setup token: {token}", flush=True)
    else:
        print("Setup token already exists on the data volume.", flush=True)

    api = _spawn(
        [
            _python(),
            "-m",
            "uvicorn",
            "agentic_soc.api:app",
            "--host",
            "0.0.0.0",
            "--port",
            "8080",
        ]
    )
    autonomy = _spawn([_python(), str(_ROOT / "scripts" / "autonomy_loop.py")])
    bot: subprocess.Popen[bytes] | None = None
    bot_sig = ""
    stopping = False

    def _shutdown(signum: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True
        print(f"appliance stopping on signal {signum}", flush=True)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    exit_code = 0
    try:
        while not stopping:
            if api.poll() is not None:
                exit_code = api.returncode or 1
                break
            if autonomy.poll() is not None:
                autonomy = _spawn([_python(), str(_ROOT / "scripts" / "autonomy_loop.py")])
            sig = _discord_signature()
            if sig != bot_sig:
                _stop(bot)
                bot = None
                bot_sig = sig
                if sig:
                    bot = _spawn([_python(), str(_ROOT / "scripts" / "discord_bot.py")])
            elif bot is not None and bot.poll() is not None and sig:
                bot = _spawn([_python(), str(_ROOT / "scripts" / "discord_bot.py")])
            time.sleep(5)
    finally:
        _stop(bot)
        _stop(autonomy)
        _stop(api)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
