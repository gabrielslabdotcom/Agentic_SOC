# Agentic SOC

AI-first SOC lab: **Wazuh** for detection, **agents + tools** for triage and investigation.

**Full setup (SSH, Wazuh Docker, native agent, Mac tools, Cursor MCP, demos, troubleshooting):** see **[docs/SETUP_GUIDE.md](docs/SETUP_GUIDE.md)**.

## Architecture

```text
Pop!_OS laptop (192.168.50.254)
  ├── Wazuh Docker single-node  (manager :55000, indexer :9200, dashboard :443)
  └── native wazuh-agent        (host telemetry → manager)

This Mac (Cursor / agent plane)
  └── Agentic_SOC               (Wazuh client, case store, MCP tools, VT enrichment)
```

## Lab endpoints (laptop)

| Service | URL |
|---------|-----|
| Dashboard | https://192.168.50.254 |
| Manager API | https://192.168.50.254:55000 |
| Indexer | https://192.168.50.254:9200 |

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

Optional HTTP tool API + analyst dashboard:

```bash
cd /Users/admin/Documents/Agentic_SOC
source .venv/bin/activate
uvicorn agentic_soc.api:app --reload --port 8080
# Dashboard: http://127.0.0.1:8080/  or  http://127.0.0.1:8080/dashboard/
# OpenAPI:   http://127.0.0.1:8080/docs
```

The dashboard lists SQLite cases, loads linked Wazuh alerts, and supports **Approve** / **Reject** (same lab-safe path as `approve_case.py` — no containment). Default `CASES_DB_PATH` is this Mac’s `data/cases.sqlite`; Pop!_OS autonomy cases are separate unless you point the API at the laptop DB or sync.

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

Fixtures live in `evals/labeled_alerts.json`. Unit checks: `pytest tests/test_triage.py tests/test_api_cases.py tests/test_cursor_agent.py`.

## Discord + Pop!_OS autonomy

```bash
# In .env: DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
python scripts/check_discord.py

# Continuous triage on the laptop (systemd) — see SETUP_GUIDE §12
# python scripts/autonomy_loop.py --once
```

New cases from the autonomy service post to Discord and stay **pending human approval**.

## Mac-offline LLM (Cursor cloud)

Optional propose-only investigation via the Cursor Python SDK cloud runtime, kicked from Pop `autonomy_loop` after Discord notify. **Not** Automations / Neo4j / Hydra; **no** auto-containment. Public cloud cannot reach LAN Wazuh without a tunnel or self-hosted pool — see **[docs/SETUP_GUIDE.md §13](docs/SETUP_GUIDE.md)**.

```bash
# On Pop (after sync):
pip install -e '.[cursor]'
# .env: AUTONOMY_CURSOR_AGENT=true, CURSOR_API_KEY=..., CURSOR_AGENT_REPO=https://github.com/...
python scripts/autonomy_loop.py --once --cursor-dry-run
```

## Next steps

1. Paste `DISCORD_WEBHOOK_URL` into `.env` on Mac and Pop!_OS; run `check_discord.py`.
2. Keep the Pop!_OS `agentic-soc-autonomy` service running; approve cases from Discord pings.
3. Optional: enable Cursor cloud investigation (§13) with `CURSOR_API_KEY` + `CURSOR_AGENT_REPO` on Pop.
4. Grow the labeled eval set; then SQLite entity correlation if multi-alert linking is needed.
5. Defer Neo4j / SOAR / Security Onion until triage is reliable.