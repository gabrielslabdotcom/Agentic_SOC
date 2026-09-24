"""Analyst closing outcomes for HITL (distinct from machine triage disposition)."""

from __future__ import annotations

from typing import Any, Optional

FALSE_POSITIVE = "false_positive"
BENIGN = "benign"
INFORMATIONAL = "informational"
DUPLICATE = "duplicate"
CONFIRMED_COMPROMISE = "confirmed_compromise"

ANALYST_DISPOSITIONS = frozenset(
    {FALSE_POSITIVE, BENIGN, INFORMATIONAL, DUPLICATE, CONFIRMED_COMPROMISE}
)

SKIP_ANALYST_DISPOSITIONS = frozenset(
    {FALSE_POSITIVE, BENIGN, INFORMATIONAL, DUPLICATE}
)

# Deprecated boolean alias used by old CLI / Discord snippets.
LEGACY_APPROVED_TO_DISPOSITION = {
    True: CONFIRMED_COMPROMISE,
    False: FALSE_POSITIVE,
}

OUTCOME_META: dict[str, dict[str, Any]] = {
    FALSE_POSITIVE: {
        "label": "False Positive",
        "skip_repeats": True,
        "description": (
            "The detector was wrong for this alert (wrong rule, self-ingest, "
            "CIS scored as attack, queue-full treated as intrusion). No incident."
        ),
    },
    BENIGN: {
        "label": "Benign",
        "skip_repeats": True,
        "description": (
            "The event is real and the rule fired correctly, but activity is "
            "authorized or expected (lab nmap, known hydra replay, MARVEL.local AD lab replay, admin typo)."
        ),
    },
    INFORMATIONAL: {
        "label": "Informational",
        "skip_repeats": True,
        "description": (
            "Awareness only; no investigation. Matches auto-close of SCA / "
            "routine agent events."
        ),
    },
    DUPLICATE: {
        "label": "Duplicate",
        "skip_repeats": True,
        "description": (
            "Same incident already triaged on another case. Distinct from "
            "false positive so metrics stay honest."
        ),
    },
    CONFIRMED_COMPROMISE: {
        "label": "Confirmed Compromise",
        "skip_repeats": False,
        "description": (
            "Malicious or lab-as-adversary activity treated as a true incident. "
            "Does not skip repeats. Does not execute containment."
        ),
    },
}


def coerce_analyst_disposition(
    *,
    disposition: Optional[str] = None,
    approved: Optional[bool] = None,
) -> str:
    """Resolve a closing outcome from disposition and/or deprecated approved flag."""
    raw = (disposition or "").strip().lower()
    if raw:
        if raw not in ANALYST_DISPOSITIONS:
            raise ValueError(
                f"unknown analyst disposition {disposition!r}; "
                f"expected one of {sorted(ANALYST_DISPOSITIONS)}"
            )
        return raw
    if approved is None:
        raise ValueError("provide disposition or approved")
    return LEGACY_APPROVED_TO_DISPOSITION[bool(approved)]


def skips_repeats(disposition: str) -> bool:
    return (disposition or "").strip().lower() in SKIP_ANALYST_DISPOSITIONS


def feedback_approved_int(disposition: str) -> int:
    """Legacy triage_feedback.approved: 0 skippable, 1 confirmed compromise."""
    return 0 if skips_repeats(disposition) else 1
