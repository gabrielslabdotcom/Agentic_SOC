"""Unit tests for triage scoring and case-open gating."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from agentic_soc.triage import (
    RULE_PORT_SCAN_LAB,
    RULE_PORT_SCAN_MULTI,
    RULE_UFW_BLOCK,
    score_alert,
    should_open_case,
)

_ROOT = Path(__file__).resolve().parents[1]
_FIXTURES = _ROOT / "evals" / "labeled_alerts.json"


def _alert(
    *,
    rule_id: str,
    rule_level: int,
    description: str,
    groups: list[str] | None = None,
    full_log: str = "",
    data: dict | None = None,
) -> dict:
    raw_rule = {
        "id": rule_id,
        "level": rule_level,
        "description": description,
        "groups": groups or [],
    }
    raw: dict = {"rule": raw_rule}
    if data:
        raw["data"] = data
    return {
        "id": f"t-{rule_id}",
        "agent": "pop-os-native",
        "rule_id": rule_id,
        "rule_level": rule_level,
        "description": description,
        "full_log": full_log,
        "raw": raw,
    }


def test_port_scan_aggregate_opens():
    alert = _alert(
        rule_id=RULE_PORT_SCAN_MULTI,
        rule_level=10,
        description="Possible port scan: multiple UFW blocks from same source.",
        groups=["firewall", "attack"],
    )
    j = score_alert(alert)
    assert j["disposition"] in ("true_positive", "suspicious")
    assert should_open_case(alert, j)["open"] is True


def test_port_scan_lab_suspicious_opens():
    alert = _alert(
        rule_id=RULE_PORT_SCAN_LAB,
        rule_level=8,
        description="Possible port scan (lab): multiple UFW BLOCK events in a short window.",
        groups=["firewall", "attack"],
    )
    j = score_alert(alert)
    assert j["disposition"] in ("suspicious", "true_positive")
    assert should_open_case(alert, j)["open"] is True


def test_lone_ufw_block_skipped():
    alert = _alert(
        rule_id=RULE_UFW_BLOCK,
        rule_level=5,
        description="UFW firewall block event.",
        full_log="[UFW BLOCK] SRC=192.168.50.9 DST=192.168.50.254 DPT=8080",
        groups=["firewall"],
        data={"srcip": "192.168.50.9"},
    )
    j = score_alert(alert)
    assert j["disposition"] in ("informational", "false_positive")
    gate = should_open_case(alert, j, sibling_alerts=[alert])
    assert gate["open"] is False
    assert gate["reason"] == "lone_ufw_block_prefer_aggregate"


def test_auth_failure_opens():
    alert = _alert(
        rule_id="5710",
        rule_level=5,
        description="sshd: authentication failed.",
        groups=["sshd", "authentication_failed"],
    )
    j = score_alert(alert)
    assert j["disposition"] == "suspicious"
    assert should_open_case(alert, j)["open"] is True


def test_missed_password_opens():
    alert = _alert(
        rule_id="5551",
        rule_level=10,
        description="syslog: User missed the password more than one time",
        groups=["syslog", "authentication_failed"],
    )
    j = score_alert(alert)
    assert j["disposition"] in ("suspicious", "true_positive")
    assert should_open_case(alert, j)["open"] is True


def test_agent_queue_full_skipped():
    alert = _alert(
        rule_id="203",
        rule_level=7,
        description="Agent event queue is full. Events may be lost.",
        groups=["ossec"],
    )
    j = score_alert(alert)
    assert j["disposition"] in ("informational", "false_positive")
    gate = should_open_case(alert, j)
    assert gate["open"] is False
    assert gate["reason"] == "agent_capacity_noise"


def test_agent_queue_full_high_level_still_skipped():
    """Even elevated rule_level must not open a case for queue-full noise."""
    alert = _alert(
        rule_id="203",
        rule_level=12,
        description="Agent event queue is full. Events may be lost.",
        groups=["ossec"],
    )
    j = score_alert(alert)
    assert j["disposition"] in ("informational", "false_positive")
    gate = should_open_case(alert, j)
    assert gate["open"] is False
    assert gate["reason"] == "agent_capacity_noise"


def test_hydra_style_auth_burst_opens():
    alert = _alert(
        rule_id="5503",
        rule_level=5,
        description="PAM: User login failed.",
        full_log=(
            "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 "
            "tty=ssh ruser= rhost=203.0.113.90  user=admin"
        ),
        groups=["pam", "syslog", "authentication_failed"],
    )
    j = score_alert(alert)
    assert j["disposition"] == "suspicious"
    assert should_open_case(alert, j)["open"] is True


def test_cis_noise_skipped():
    alert = _alert(
        rule_id="19005",
        rule_level=7,
        description="CIS Distribution Independent Linux Benchmark v2.0.0.: Ensure root PATH Integrity.",
        groups=["sca", "cis"],
    )
    j = score_alert(alert)
    assert j["disposition"] in ("informational", "false_positive")
    assert should_open_case(alert, j)["open"] is False


def test_labeled_fixture_thresholds():
    spec = importlib.util.spec_from_file_location(
        "eval_triage",
        _ROOT / "scripts" / "eval_triage.py",
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    report = mod.run_eval(_FIXTURES)
    assert report["passed"], report.get("failures")
    assert report["disposition_accuracy"] >= 0.8
    assert report["open_case_accuracy"] >= 0.85


def test_labeled_json_loadable():
    data = json.loads(_FIXTURES.read_text())
    assert 10 <= len(data["alerts"]) <= 25
