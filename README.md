# Agentic SOC

AI-first SOC lab: **Wazuh** for detection, **agents + tools** for triage and investigation.

**Full setup (SSH, Wazuh Docker, native agent, Mac tools, Cursor MCP, demos, troubleshooting):** see **[docs/SETUP_GUIDE.md](docs/SETUP_GUIDE.md)**.

## Architecture

```text
Pop!_OS laptop (192.168.50.254)
  ├── Wazuh Docker single-node  (manager :55000, indexer :9200, dashboard :443)
  ├── native wazuh-agent        (host telemetry → manager)
  ├── autonomy systemd          (Discord + Cursor cloud hook → laptop cases.sqlite)
  └── FastAPI analyst UI        (127.0.0.1:8080 — live Pop cases)

This Mac (Cursor / agent plane)
  └── Agentic_SOC               (MCP, local cases.sqlite — a separate copy)
      ssh -L 8081:127.0.0.1:8080 soc   → view Pop / Discord cases (or ./scripts/tunnel_pop_dashboard.sh)
```

## Lab endpoints (laptop)

| Service | URL |
|---------|-----|
| Wazuh dashboard | https://192.168.50.254 |
| Manager API | https://192.168.50.254:55000 |
| Indexer | https://192.168.50.254:9200 |
| Analyst UI (Pop cases) | `ssh -L 8081:127.0.0.1:8080 soc` (or `./scripts/tunnel_pop_dashboard.sh`) → http://127.0.0.1:8081/ |

Default **lab-only** credentials (change before any non-lab use):

| Surface | User | Password |
|---------|------|----------|
| Dashboard / Indexer | `admin` | `SecretPassword` |
| Manager API | `wazuh-wui` | `MyS3cr37P450r.*-` |

Wazuh lives at `/home/admin/wazuh-docker/single-node` on the laptop (`ssh soc`).

## Quick start (this repo)

```bash
cd /Users/admin/Documents/Agentic_SOC
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

| Cases you want | How |
|----------------|-----|
| **Live Discord / autonomy cases on Pop** | `./scripts/tunnel_pop_dashboard.sh` then http://127.0.0.1:8081/ (banner: **LIVE Pop cases**). Pop FastAPI is `127.0.0.1:8080`; tunnel uses **8081** so a Mac uvicorn on 8080 cannot shadow it. |
| **This Mac’s local copy** | `uvicorn agentic_soc.api:app --reload --port 8080` — uses this repo’s `data/cases.sqlite` (banner: **Mac local copy**) |

```bash
# Mac-local API only (not the Discord/autonomy DB)
cd /Users/admin/Documents/Agentic_SOC
source .venv/bin/activate
uvicorn agentic_soc.api:app --reload --port 8080
# OpenAPI: http://127.0.0.1:8080/docs
```

**Approve / Reject** record status + a note only (same as `approve_case.py`). No containment. The dashboard glossary and Discord embed field say the same thing. Case detail also shows **Related cases** via SQLite `find_related` (same source IP / hash / user / domain).

## Cursor MCP

Project config is at [`.cursor/mcp.json`](.cursor/mcp.json). In Cursor: **Settings → MCP** and enable **agentic-soc** (or reload MCP servers). It runs:

```bash
/Users/admin/Documents/Agentic_SOC/.venv/bin/python -m agentic_soc.mcp_server
```

## Agent tool surface

| Tool | Purpose |
|------|---------|
| `list_agents` | Agent inventory + status |
| `list_alerts` | Recent alerts from the indexer |
| `get_alert` | Fetch one alert by id |
| `open_case` / `get_case` / `update_case` / `list_cases` | Local SQLite case memory |
| `propose_action` | Log-only response recommendation (no auto-containment) |
| `approve_case` | Human approve/reject (status + notes only; no containment) |
| `upsert_entity` / `link_alert_to_entity` / `link_case_to_entity` / `find_related` | SQLite entity correlation (not Neo4j) |
| `enrich_ioc` | VirusTotal lookup for ip / domain / url / hash |

## Closed-loop triage

```bash
# Score recent alerts, enrich external IOCs, open cases (skip benign noise)
python scripts/agent_triage.py --agent-name pop-os-native --min-level 5

# Preview only (no case writes)
python scripts/agent_triage.py --dry-run --min-level 3 --limit 20

# Save a JSON report while you generate events on the laptop
python scripts/agent_triage.py --min-level 3 --json-out data/triage_report.json

# Generate nmap-style traffic so Wazuh sees port scans (needs UFW on the laptop)
python scripts/generate_portscan_lab.py --host 192.168.50.254
```

Uses heuristics in `src/agentic_soc/triage.py` plus VirusTotal when public IOCs appear. Never auto-contains.

- Prefer aggregate port-scan rules `100101` / `100102`; lone UFW BLOCK `100100` is demoted / skipped
- Auth failures → suspicious + open case; CIS/SCA → informational + skip
- See [docs/SETUP_GUIDE.md](docs/SETUP_GUIDE.md) **§8.1** (UFW) and **§11** (end-user workflow: generate → triage → eval → approve)

## Eval + human approval

```bash
# Labeled triage quality (exits non-zero if below threshold)
python scripts/eval_triage.py

# Approve / reject a proposed action (still no auto-containment)
python scripts/approve_case.py --case-id 1 --approve --note "looks like lab scan"
python scripts/approve_case.py --case-id 1 --reject --note "noise"
```

Fixtures live in `evals/labeled_alerts.json`. Unit checks: `pytest tests/ -q`.

## Discord + Pop!_OS autonomy (already live)

Pop `agentic-soc-autonomy` is running: `AUTONOMY_MIN_LEVEL=8`, excludes lone UFW `100100`, Discord notifies, `AUTONOMY_CURSOR_AGENT=true`. New cases land in **Pop** `/home/admin/Agentic_SOC/data/cases.sqlite` and stay pending human approval (record-only Approve / Reject).

Auth failures at Wazuh **level 5** are covered by the eval harness, but the **live loop does not fetch them** (min-level 8). That is deliberate noise control until Phase C.

```bash
# Status from this Mac
python scripts/lab_status.py

# Logs / one-shot (do not overwrite Pop .env)
ssh soc 'journalctl --user -u agentic-soc-autonomy.service -f'
# Restart: systemctl --user restart is preferred (TimeoutStopSec=90).
# SIGKILL only if it still hangs — SETUP_GUIDE §12.3
```

Open live cases from the Mac: `./scripts/tunnel_pop_dashboard.sh` → http://127.0.0.1:8081/

## Mac-offline LLM (Cursor cloud — already enabled)

Propose-only Cursor SDK **cloud** agent, kicked from Pop after Discord notify. Repo `https://github.com/gabrielslabdotcom/Agentic_SOC`; Cursor GitHub App SCM access is granted (clone works). No-repo fallback remains if SCM fails. **Not** Automations / Neo4j / **Hydra** (Hydra breaks `sshd`). **No** auto-containment. Public cloud cannot reach LAN Wazuh without a tunnel or self-hosted pool — see **[docs/SETUP_GUIDE.md §13](docs/SETUP_GUIDE.md)**.

```bash
# Dry-run on Pop (no need to re-set keys)
ssh soc 'cd /home/admin/Agentic_SOC && source .venv/bin/activate && python scripts/autonomy_loop.py --once --cursor-dry-run --no-discord'
```

## Next steps

Phase A (HITL ops) is in this repo: instance banners, tunnel on **8081**, `lab_status.py`, unique `alert_id`, `since` cursor on the autonomy poll. After rsync + unit-file refresh on Pop, prefer `systemctl --user restart` over SIGKILL.

1. Keep `agentic-soc-autonomy` and `agentic-soc-dashboard` running on Pop; review Discord pings and Approve / Reject via the **8081** tunneled dashboard (record-only). **No auto-containment.**
2. **Phase B (later):** close the Cursor investigation loop so notes land on the case — still no containment.
3. **Phase C (later):** triage quality — grow `evals/labeled_alerts.json`; decide whether live min-level 8 should also ingest auth L5; learn from Approve / Reject. Do **not** lower `AUTONOMY_MIN_LEVEL` until that phase.
4. Entity correlation stays SQLite (`find_related`). Defer Neo4j / SOAR / Security Onion / Hydra.