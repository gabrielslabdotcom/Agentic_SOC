# Cursor cloud

Operator detail: [SETUP_GUIDE.md §13](../SETUP_GUIDE.md).

After a HITL case opens, Pop kicks a **Cursor SDK cloud** agent (`AUTONOMY_CURSOR_AGENT=true`). The VM clones `CURSOR_AGENT_REPO` (this GitHub repo when SCM access is granted). When `Agent.prompt` returns, **Pop copies the final reply onto the SQLite case** and Discord sends a follow-up. The Mac does not need to be online.

This is **not** Automations, **not** Neo4j, **not Hydra**. Hydra interferes with `sshd` on this lab — do not enable it.

## Propose only

The cloud agent must **not** Approve/Reject or execute containment. Public cloud VMs **cannot** reach `192.168.50.254`. That is why Pop persists the note locally.

| Path | Live Wazuh from the VM? | Note on the case? |
|------|-------------------------|-------------------|
| Public cloud (this lab) | No | Yes — Pop copies the final reply |
| Extra tunnel | If you expose APIs | Optional HTTP write-back |
| Self-hosted pool on Pop | Yes | Yes |

Store `CURSOR_API_KEY` only in `.env`. Never commit it.

## Dry-run

```bash
ssh soc 'cd /home/admin/Agentic_SOC && source .venv/bin/activate && python scripts/autonomy_loop.py --once --cursor-dry-run --no-discord'
```

## SCM failures

If the Cursor GitHub App cannot see the repo, autonomy logs a validation error and (by default) retries **no-repo** (case JSON only). Grant the App access to `gabrielslabdotcom/Agentic_SOC` to restore clones. Discord/case open still succeeded.

Dashboard: **Cursor investigation** on the case, above analyst outcomes.

Next: [Containment](containment.md) · [Roadmap](roadmap.md).
