#!/usr/bin/env python3
"""Run the Discord Gateway bot for analyst-outcome buttons (outbound only)."""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from agentic_soc.discord_bot import run_bot  # noqa: E402


def main() -> None:
    run_bot()


if __name__ == "__main__":
    main()
