#!/usr/bin/env python3
"""Fail if public tree still contains lab-specific IPs, paths, or passwords.

Scans README, .env.example, src/, frontend/src/, deploy/ (except gitignored HARDENING.md).
Does not scan tests/, evals/, node_modules, or operator-only scripts.
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
    ("SSH host alias `soc`", re.compile(r"\bssh\s+soc\b", re.I)),
    ("lab agent pop-os-native", re.compile(r"pop-os-native")),
    ("lab agent Clean-Win10", re.compile(r"Clean[_-]?Win10", re.I)),
    ("lab agent Win10-SOC", re.compile(r"Win10-SOC", re.I)),
    ("lab host HYDRA-DC", re.compile(r"HYDRA-DC")),
    ("lab domain MARVEL.local", re.compile(r"MARVEL\.local", re.I)),
]

SKIP_DIR_NAMES = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "__pycache__",
    ".pytest_cache",
    "tests",
    "evals",
}

SKIP_FILES = {
    "HARDENING.md",
    "lab_status.py",
    "tunnel_pop_dashboard.sh",
    "check_docs_sanitized.py",  # contains forbidden patterns as literals
}

SCAN_SUFFIXES = {".py", ".md", ".tsx", ".ts", ".html", ".xml", ".snippet", ".service", ".example", ".conf", ".yml", ".yaml", ".json", ".sh"}


def iter_public_files() -> list[Path]:
    files: list[Path] = [ROOT / "README.md", ROOT / ".env.example"]
    for rel in ("src", "frontend/src", "deploy", "scripts"):
        base = ROOT / rel
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            if any(part in SKIP_DIR_NAMES for part in path.parts):
                continue
            if path.name in SKIP_FILES:
                continue
            if path.suffix and path.suffix not in SCAN_SUFFIXES:
                # Allow suffix-less only for known text? skip binaries
                if path.suffix not in {".svg", ".png", ".jpg", ".woff", ".woff2"}:
                    if path.suffix not in SCAN_SUFFIXES:
                        continue
                else:
                    continue
            if path.suffix not in SCAN_SUFFIXES and path.name not in {".env.example"}:
                continue
            files.append(path)
    # Deduplicate while preserving order
    seen: set[Path] = set()
    out: list[Path] = []
    for p in files:
        rp = p.resolve()
        if rp not in seen and p.is_file():
            seen.add(rp)
            out.append(p)
    return out


def main() -> int:
    violations: list[str] = []
    scanned = iter_public_files()
    for path in scanned:
        text = path.read_text(encoding="utf-8", errors="replace")
        rel = path.relative_to(ROOT)
        for label, pattern in FORBIDDEN:
            for i, line in enumerate(text.splitlines(), start=1):
                if pattern.search(line):
                    violations.append(f"{rel}:{i}: {label}: {line.strip()[:120]}")
    if violations:
        print("Public tree still contains lab-specific values:\n", file=sys.stderr)
        for v in violations:
            print(f"  {v}", file=sys.stderr)
        print(
            "\nUse placeholders (<SIEM_HOST>, $AGENTIC_SOC_HOME, RFC5737 docs IPs, …). "
            "Real values belong in gitignored local notes.",
            file=sys.stderr,
        )
        return 1
    print(f"OK — scanned {len(scanned)} public file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
