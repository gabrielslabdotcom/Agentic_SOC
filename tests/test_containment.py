"""HITL containment plan safety (dry-run by default)."""

from __future__ import annotations

from agentic_soc.containment import execute_block_source_ip, plan_block_source_ip


def test_plan_allows_external_attacker_ip() -> None:
    plan = plan_block_source_ip("203.0.113.50", case_id=12)
    assert plan["allowed"] is True
    assert plan.get("executed") is not True
    assert plan["dry_run"] is True
    assert "203.0.113.50" in plan["command"]
    assert "sudo -n ufw insert 1 deny from 203.0.113.50" in plan["command"]


def test_plan_blocks_pop_host() -> None:
    plan = plan_block_source_ip("192.168.50.254", case_id=1)
    assert plan["allowed"] is False
    assert plan["reason"] == "protected_lab_host"
    assert plan["command"] is None


def test_plan_blocks_loopback() -> None:
    plan = plan_block_source_ip("127.0.0.1")
    assert plan["allowed"] is False
    assert plan["command"] is None


def test_plan_rejects_blank() -> None:
    plan = plan_block_source_ip("")
    assert plan["allowed"] is False
    assert plan["reason"] == "no_source_ip"


def test_execute_without_confirm_is_noop() -> None:
    result = execute_block_source_ip("203.0.113.50", case_id=3, confirm=False)
    assert result["executed"] is False
    assert result["reason"] == "confirm_required"


def test_execute_disabled_by_default(monkeypatch) -> None:
    monkeypatch.delenv("CONTAINMENT_ENABLED", raising=False)
    result = execute_block_source_ip("203.0.113.50", case_id=3, confirm=True)
    assert result["executed"] is False
    assert result["reason"] == "containment_disabled"


def test_execute_when_enabled_runs_argv(monkeypatch) -> None:
    monkeypatch.setenv("CONTAINMENT_ENABLED", "true")
    monkeypatch.setattr("agentic_soc.containment.shutil.which", lambda _: "/usr/bin/mock")

    class _Proc:
        returncode = 0
        stdout = "Rule inserted"
        stderr = ""

    def _run(argv, **kwargs):
        assert argv[:6] == ["sudo", "-n", "ufw", "insert", "1", "deny"]
        return _Proc()

    monkeypatch.setattr("agentic_soc.containment.subprocess.run", _run)
    result = execute_block_source_ip("198.51.100.20", case_id=9, confirm=True)
    assert result["executed"] is True
    assert result["ok"] is True
