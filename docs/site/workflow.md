# Analyst workflow

Operator detail: [SETUP_GUIDE.md §8.1, §11](../SETUP_GUIDE.md).

**Generate → wait for indexer → triage / autonomy → review Discord → Approve or Reject on the tunneled dashboard.**

## Generate lab events

Port scan (UFW + custom rules `100100` / `100101` / `100102`):

```bash
python scripts/generate_portscan_lab.py --host 192.168.50.254
```

Wait ~15–30s. A host agent does **not** see raw packets; it needs UFW logging + local rules. Do **not** `ufw allow from 192.168.50.0/24` or BLOCK logs disappear.

Optional: a few failed SSH logins from another host (do not lock yourself out).

## Manual triage (Mac)

```bash
python scripts/agent_triage.py --agent-name pop-os-native --min-level 5 --dry-run --limit 30
python scripts/agent_triage.py --agent-name pop-os-native --min-level 5 --max-cases 8
```

Live autonomy on Pop already does this on an interval.

| Alert type | Typical disposition | Case? |
|------------|---------------------|--------|
| Port-scan aggregate `100101` / `100102` | suspicious / true_positive | yes |
| Auth failure | suspicious | yes |
| CIS / SCA | informational / false_positive | no (under threshold) |
| Lone UFW `100100` | informational | no |
| Agent queue full | informational / false_positive | no |

## Review

- Discord embed (case opened, then investigation note ready)
- http://127.0.0.1:8081/ — bulk Approve / Reject, related cases, Cursor note, containment **plan**

**Approve** = accept triage (document only). **Reject** = noise / wrong proposal. Neither runs UFW. Reject on the same `rule_id` + source IP skips repeats (~14 days).

CLI: `python scripts/approve_case.py --case-id N --approve|--reject --note "..."`.

Next: [Triage quality](triage-quality.md) and [Cursor cloud](cursor-cloud.md).
