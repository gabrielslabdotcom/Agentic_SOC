# Triage quality

This lab does **not** train or fine-tune a model. Quality is heuristics + labels + your decisions.

## Labeled eval (not ML training)

Fixtures: `evals/labeled_alerts.json`. Harness:

```bash
python scripts/eval_triage.py
```

Floors live in the fixture JSON (disposition ~80%, open-case ~85%). Heuristics: `src/agentic_soc/triage.py`. When a live miss happens, add a **sanitized** fixture and re-run. That is the baseline.

## Human feedback (skip keys)

Approve / Reject write `triage_feedback`. A **False Positive / Benign / Informational / Duplicate** on the same `rule_id` + source IP skips opening repeats for 14 days (not a global rule demotion). **Confirmed Compromise** does not skip.

```bash
# Against the cases DB in CASES_DB_PATH (use Pop's path over SSH for live keys)
python scripts/eval_feedback.py
```

## Auto-close noise (Phase D)

If a case would still open and the heuristic says `informational` or `false_positive`, the loop records status **`auto_closed`** and **does not** Discord or Cursor. Suspicious / true-positive stay HITL. VirusTotal `malicious > 0` stays HITL. Auto-closed cases do not count against `AUTONOMY_MAX_CASES`.

Live poll: `(level ≥ 8) OR (sshd/PAM auth failure at level ≥ 5)` via `AUTONOMY_INCLUDE_AUTH`. Do **not** lower `AUTONOMY_MIN_LEVEL` to 5.

Next: [Containment](containment.md).
