#!/usr/bin/env python3
"""Fail if public docs still contain lab-specific IPs, paths, or passwords.

Scans only: README.md, .env.example
Does not scan tests, evals, or deploy units.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Patterns that must not appear on the public surface.
FORBIDDEN: list[tuple[str, re.Pattern[str]]] = [
    ("private LAN IP (192.168.)", re.compile(r"192\.168\.")),
    ("home path /home/admin", re.compile(r"/home/admin")),
    ("Mac path /Users/admin", re.compile(r"/Users/admin")),
    ("GitHub org gabrielslabdotcom", re.compile(r"gabrielslabdotcom", re.I)),
    ("lab password SecretPassword", re.compile(r"SecretPassword")),
    ("lab password MyS3cr37", re.compile(r"MyS3cr37")),
]


def iter_public_files() -> list[Path]:
    files: list[Path] = [ROOT / "README.md", ROOT / ".env.example"]
    return [p for p in files if p.is_file()]


def main() -> int:
    violations: list[str] = []
    for path in iter_public_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        rel = path.relative_to(ROOT)
        for label, pattern in FORBIDDEN:
            for i, line in enumerate(text.splitlines(), start=1):
                if pattern.search(line):
                    violations.append(f"{rel}:{i}: {label}: {line.strip()[:120]}")
    if violations:
        print("Public docs still contain lab-specific values:\n", file=sys.stderr)
        for v in violations:
            print(f"  {v}", file=sys.stderr)
        print(
            "\nUse placeholders (<SIEM_HOST>, $AGENTIC_SOC_HOME, …). "
            "Real values belong in gitignored local notes.",
            file=sys.stderr,
        )
        return 1
    print(f"OK — scanned {len(iter_public_files())} public doc file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
