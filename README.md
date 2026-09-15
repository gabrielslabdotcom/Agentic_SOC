# Agentic SOC

AI-first SOC lab: **Wazuh** for detection, **agents + tools** for triage and investigation.

## Architecture

```text
Pop!_OS laptop (<SIEM_HOST>)
  ├── Wazuh Docker single-node  (manager :55000, indexer :9200, dashboard :443)
  ├── native wazuh-agent        (host telemetry → manager)
  ├── autonomy systemd          (Discord + Cursor cloud hook → laptop cases.sqlite)
  └── FastAPI analyst UI        (0.0.0.0:8080, UFW allowlisted — live Pop cases)

This Mac (Cursor / agent plane)
  └── Agentic_SOC               (MCP, local cases.sqlite — a separate copy)
      live UI: http://<SIEM_HOST>:8080/   (Mac uvicorn :8080 is the local copy only)
```



## Lab endpoints (laptop)


| Service                | URL                                                                     |
| ---------------------- | ----------------------------------------------------------------------- |
| Wazuh dashboard        | https://                                                                |
| Manager API            | https://:55000                                                          |
| Indexer                | https://:9200                                                           |
| Analyst UI (Pop cases) | http://:8080/ (UFW allowlisted; Mac uvicorn on :8080 is the local copy) |


## Quick start (this repo)

```bash
cd $AGENTIC_SOC_HOME
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
cp .env.example .env
# set VIRUSTOTAL_API_KEY in .env (never commit it)

python scripts/check_wazuh.py
python scripts/check_virustotal.py
python scripts/triage_demo.py
python scripts/agent_triage.py --min-level 5 --max-cases 8
python scripts/eval_triage.py
```

Analyst dashboard (two DBs — they are not synced):


| Cases you want                           | How                                                                                                                                                                                                                         |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Live Discord / autonomy cases on Pop** | http://:8080/ (banner: **LIVE Pop cases**). UFW allows TCP 8080 only from this Mac (and optionally Kali). Optional tunnel fallback: `./scripts/tunnel_pop_dashboard.sh` → [http://127.0.0.1:8081/](http://127.0.0.1:8081/). |
| **This Mac’s local copy**                | `uvicorn agentic_soc.api:app --reload --port 8080` — uses this repo’s `data/cases.sqlite` (banner: **Mac local copy**). Not Discord cases.                                                                                  |


```bash
# Mac-local API only (not the Discord/autonomy DB)
cd $AGENTIC_SOC_HOME
source .venv/bin/activate
uvicorn agentic_soc.api:app --reload --port 8080
# OpenAPI: http://127.0.0.1:8080/docs
```

**Analyst outcomes** record status + a note only (same as `approve_case.py`). They do **not** run UFW. A separate **Containment plan** on the case is a dry-run unless `CONTAINMENT_ENABLED=true` and you click Execute.

## Cursor MCP

Project config is at `[.cursor/mcp.json](.cursor/mcp.json)`. In Cursor: **Settings → MCP** and enable **agentic-soc** (or reload MCP servers). It runs:

```bash
$AGENTIC_SOC_HOME/.venv/bin/python -m agentic_soc.mcp_server
```



## Agent tool surface


| Tool                                                                              | Purpose                                                     |
| --------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| `list_agents`                                                                     | Agent inventory + status                                    |
| `list_alerts`                                                                     | Recent alerts from the indexer                              |
| `get_alert`                                                                       | Fetch one alert by id                                       |
| `open_case` / `get_case` / `update_case` / `list_cases`                           | Local SQLite case memory                                    |
| `propose_action`                                                                  | Log-only response recommendation (no auto-containment)      |
| `approve_case`                                                                    | Human closing outcome (status + notes only; no containment) |
| `upsert_entity` / `link_alert_to_entity` / `link_case_to_entity` / `find_related` | SQLite entity correlation (not Neo4j)                       |
| `enrich_ioc`                                                                      | VirusTotal lookup for ip / domain / url / hash              |




## Closed-loop triage

```bash
# Score recent alerts, enrich external IOCs, open cases (skip benign noise)
python scripts/agent_triage.py --agent-name pop-os-native --min-level 5

# Preview only (no case writes)
python scripts/agent_triage.py --dry-run --min-level 3 --limit 20

# Save a JSON report while you generate events on the laptop
python scripts/agent_triage.py --min-level 3 --json-out data/triage_report.json

# Generate nmap-style traffic so Wazuh sees port scans (needs UFW on the laptop)
python scripts/generate_portscan_lab.py --host <SIEM_HOST>
```

Uses heuristics in `src/agentic_soc/triage.py` plus VirusTotal when public IOCs appear. Never auto-contains.

- Prefer aggregate port-scan rules `100101` / `100102`; lone UFW BLOCK `100100` is demoted / skipped
- Auth failures → suspicious + open case; CIS/SCA → informational + skip
- See [docs/SETUP_GUIDE.md](docs/SETUP_GUIDE.md) **§8.1** (UFW) and **§11** (end-user workflow: generate → triage → eval → approve)



## Eval + human approval

```bash
# Labeled triage quality (exits non-zero if below threshold)
python scripts/eval_triage.py
python scripts/eval_feedback.py

# Approve / reject a proposed action (still no auto-containment)
python scripts/approve_case.py --case-id 1 --disposition benign --note "looks like lab scan"
python scripts/approve_case.py --case-id 1 --disposition false_positive --note "noise"
```

Fixtures live in `evals/labeled_alerts.json`. Unit checks: `pytest tests/ -q`.

## Discord + Pop!_OS autonomy (already live)

Pop `agentic-soc-autonomy` is running: `AUTONOMY_MIN_LEVEL=8`, `AUTONOMY_INCLUDE_AUTH=true` (auth L5 OR'd in), `AUTONOMY_FEEDBACK_SKIP=true`, `AUTONOMY_AUTO_CLOSE_NOISE=true`, excludes lone UFW `100100`, Discord notifies, `AUTONOMY_CURSOR_AGENT=true`. New **suspicious** cases land in **Pop** `$AGENTIC_SOC_HOME/data/cases.sqlite` and stay pending human approval. Informational / FP that still pass the open gate auto-close without Discord.

Optional **Gateway bot** (`agentic-soc-discord-bot`, `pip install -e '.[discord]'`, `DISCORD_BOT_TOKEN` + `DISCORD_CHANNEL_ID`): case-opened embeds include five analyst-outcome buttons. Clicks close via `resolve_proposal` over an **outbound** websocket only (no Interactions HTTP URL / no new inbound port). Incoming webhook remains the fallback. Setup: **[docs/SETUP_GUIDE.md §12.1](docs/SETUP_GUIDE.md)**.

Auth failures at Wazuh **level 5** are OR'd into the live indexer query (`AUTONOMY_INCLUDE_AUTH`, default on) without lowering `AUTONOMY_MIN_LEVEL` from 8. A human **False Positive / Benign / Informational / Duplicate** on the same `rule_id` + source IP skips repeats for 14 days. **Confirmed Compromise** does not skip. Informational / false-positive cases that still pass the open gate may **auto-close** (`AUTONOMY_AUTO_CLOSE_NOISE`) without Discord or Cursor. Suspicious / true-positive stay HITL. Containment is still never executed.

```bash
# Status from this Mac
python scripts/lab_status.py

# Logs / one-shot (do not overwrite Pop .env)
ssh <ssh-alias> 'journalctl --user -u agentic-soc-autonomy.service -f'
# Restart: systemctl --user restart is preferred (TimeoutStopSec=90).
# SIGKILL only if it still hangs — SETUP_GUIDE §12.3
```

Open live cases from the Mac: **http://:8080/** (banner **LIVE Pop cases**). Mac `uvicorn --port 8080` is the local fixture DB only. Tunnel `8081` is an optional fallback.

## Mac-offline LLM (Cursor cloud — already enabled)

Propose-only Cursor SDK **cloud** agent, kicked from Pop after Discord notify. When the run finishes, **Pop copies the final reply onto the case** and Discord sends a follow-up. Repo `https://github.com/<your-org>/Agentic_SOC`; Cursor GitHub App SCM access is granted (clone works). No-repo fallback remains if SCM fails. **Not** Automations / Neo4j / **Hydra** (Hydra breaks `sshd`). **No** auto-containment. Public cloud still cannot reach LAN Wazuh — see **[docs/SETUP_GUIDE.md §13](docs/SETUP_GUIDE.md)**.

```bash
# Dry-run on Pop (no need to re-set keys)
ssh <ssh-alias> 'cd $AGENTIC_SOC_HOME && source .venv/bin/activate && python scripts/autonomy_loop.py --once --cursor-dry-run --no-discord'
```

## Next steps

Phase A (HITL ops) is in this repo: instance banners, LAN analyst UI on **http://:8080/**, `lab_status.py`, unique `alert_id`, `since` cursor on the autonomy poll. After rsync + unit-file refresh on Pop, prefer `systemctl --user restart` over SIGKILL.

1. Keep `agentic-soc-autonomy` and `agentic-soc-dashboard` running on Pop; review Discord pings (case opened **and** investigation note ready) and record an analyst outcome via Discord buttons or **http://:8080/** (record-only). **No auto-containment.**
2. **Phase B:** Cursor final reply is stored on the case; dashboard shows **Cursor investigation**; Discord follow-up when it lands.
3. **Phase C:** live auth L5 via OR query (min-level stays 8); False Positive / Benign / Informational / Duplicate skip on `rule_id`+source IP; grown `evals/labeled_alerts.json` plus `python scripts/eval_feedback.py`. Optional Gateway bot unit for outcome buttons (§12.1).
4. **Phase D:** limited auto-close of informational / false-positive noise (`AUTONOMY_AUTO_CLOSE_NOISE`) — no Discord, no Cursor. Suspicious stays HITL.
5. **Phase E (this repo):** HITL containment *plan* — record `sudo -n ufw deny from <src>` on the case. Execute requires `CONTAINMENT_ENABLED=true` plus a separate dashboard click. Analyst outcomes / autonomy never run UFW. Auto-containment stays deferred.
6. Entity correlation stays SQLite (`find_related`). Defer Neo4j / SOAR / Security Onion / Hydra.

