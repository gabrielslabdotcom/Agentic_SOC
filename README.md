# Agentic SOC

AI-first SOC lab: **Wazuh** for detection, **agents + tools** for triage and investigation. Human-in-the-loop (HITL) only — **no auto-containment**.

## Quick start

This repo is the **Agentic SOC app** (Python tools, analyst UI, optional autonomy/Discord/Cursor). Wazuh itself is installed separately — use the official [wazuh-docker](https://github.com/wazuh/wazuh-docker) single-node guide (or any Wazuh manager + indexer you already run).

### Prerequisites

- Python **3.11+**
- A reachable Wazuh manager API (`:55000`) and indexer (`:9200`)
- Optional: Discord webhook or bot token, VirusTotal key, Cursor API key (see [`.env.example`](.env.example))

### Bootstrap the app

```bash
git clone <this-repo> Agentic_SOC
cd Agentic_SOC
./scripts/bootstrap_app.sh          # venv + pip install -e '.[dev]' + .env if missing
# or with extras:
# ./scripts/bootstrap_app.sh --extras cursor,discord
source .venv/bin/activate
```

Manual equivalent:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'             # add ,cursor and/or ,discord as needed
cp -n .env.example .env             # do not overwrite an existing .env
```

| Extra | Install | Used for |
| ----- | ------- | -------- |
| (none) | `pip install -e .` | Core API, MCP, triage scripts |
| `dev` | `pip install -e '.[dev]'` | pytest |
| `discord` | `pip install -e '.[discord]'` | Gateway bot (`agentic-soc-discord-bot`) |
| `cursor` | `pip install -e '.[cursor]'` | Cursor cloud investigation from autonomy |

### Configure `.env`

1. Copy [`.env.example`](.env.example) → `.env` (bootstrap does this once).
2. Set `WAZUH_API_URL`, `WAZUH_INDEXER_URL`, and credentials for **your** SIEM.
   - On the SIEM host itself, prefer `https://127.0.0.1:55000` / `:9200` (already noted in `.env.example`).
   - From another machine, use `https://<SIEM_HOST>:…`.
3. Set `CASES_DB_PATH` (default `data/cases.sqlite`). Live Pop autonomy and a workstation MCP copy are **separate** files — they are not synced.
4. **Always set `.env`.** Do not rely on code defaults in `config.py` for URLs or passwords.
5. Never commit `.env`.

### Run locally

```bash
source .venv/bin/activate
python scripts/check_wazuh.py       # manager + indexer smoke test
uvicorn agentic_soc.api:app --host 127.0.0.1 --port 8080
# open http://127.0.0.1:8080/
```

### Linux SIEM host (optional systemd)

Units under [`deploy/`](deploy/) are templates. Copy them, replace every hardcoded install path with your `$AGENTIC_SOC_HOME` (WorkingDirectory, EnvironmentFile, ExecStart / venv python), then:

```bash
mkdir -p ~/.config/systemd/user
cp deploy/agentic-soc-*.service ~/.config/systemd/user/
# edit paths in those copies
systemctl --user daemon-reload
systemctl --user enable --now agentic-soc-autonomy.service agentic-soc-dashboard.service
# optional: agentic-soc-discord-bot.service after pip install -e '.[discord]'
loginctl enable-linger "$USER"   # keep user units after logout
```

Bind the dashboard only as needed; the API has no login — restrict access (e.g. firewall allowlist) rather than exposing `:8080` to an entire LAN.

### Cursor MCP (optional)

Point Cursor at the repo venv with cwd = repo root (no machine-specific home paths in git):

```json
{
  "mcpServers": {
    "agentic-soc": {
      "command": "${workspaceFolder}/.venv/bin/python",
      "args": ["-m", "agentic_soc.mcp_server"],
      "cwd": "${workspaceFolder}"
    }
  }
}
```

If your Cursor build does not expand `${workspaceFolder}`, substitute the absolute path to this clone.

### Optional Wazuh detection snippets

[`deploy/wazuh/`](deploy/wazuh/) has lab-oriented `local_rules.xml`, `local_decoder.xml`, and a remote-syslog snippet. Merge them into **your** manager if you want similar UFW / port-scan detections. Edit syslog `allowed-ips` to your own syslog source — do not copy another lab’s LAN addresses.

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

Two `cases.sqlite` stores are **not synced**. Live Discord / autonomy cases live on Pop (`$AGENTIC_SOC_HOME/data/cases.sqlite`). This Mac’s repo file is a local fixture/copy only.

| Service                | URL |
| ---------------------- | --- |
| Wazuh dashboard        | `https://<SIEM_HOST>` |
| Manager API            | `https://<SIEM_HOST>:55000` |
| Indexer                | `https://<SIEM_HOST>:9200` |
| Analyst UI (Pop cases) | `http://<SIEM_HOST>:8080/` (UFW allowlisted; banner **LIVE Pop cases**) |

## What’s running

**On Pop**

- Wazuh Docker (manager, indexer, dashboard) and a native `wazuh-agent`
- `agentic-soc-autonomy` — polls the indexer, opens cases, Discord notifies, optional Cursor cloud investigation
- FastAPI analyst UI on `:8080` (UFW allowlisted)
- Optional Discord Gateway bot (`agentic-soc-discord-bot`) for analyst-outcome buttons (outbound websocket only; webhook remains fallback)
- Cursor SDK **cloud** agent (propose-only): after Discord notify, Pop copies the final reply onto the case and can send a Discord follow-up

**On this Mac**

- Cursor MCP (`agentic-soc`) against this repo’s local SQLite
- Mac-local API/UI is the fixture DB only (banner **Mac local copy**), not Discord cases

## Triage / HITL behavior

- Autonomy uses `AUTONOMY_MIN_LEVEL=8`; auth failures at Wazuh **level 5** are OR’d in (`AUTONOMY_INCLUDE_AUTH`) without lowering the min level
- Lone UFW BLOCK rule `100100` is excluded; prefer aggregate port-scan rules `100101` / `100102`
- Human **False Positive / Benign / Informational / Duplicate** on the same `rule_id` + source IP skips repeats for 14 days (`AUTONOMY_FEEDBACK_SKIP`). **Confirmed Compromise** does not skip
- Informational / false-positive cases that still pass the open gate may **auto-close** (`AUTONOMY_AUTO_CLOSE_NOISE`) without Discord or Cursor. Suspicious / true-positive stay HITL
- Analyst outcomes record status + note only — they do **not** run UFW
- Containment plan on a case is dry-run unless `CONTAINMENT_ENABLED=true` and an analyst explicitly Executes. Autonomy never executes containment

## Agent tool surface

| Tool | Purpose |
| ---- | ------- |
| `list_agents` | Agent inventory + status |
| `list_alerts` | Recent alerts from the indexer |
| `get_alert` | Fetch one alert by id |
| `open_case` / `get_case` / `update_case` / `list_cases` | Local SQLite case memory |
| `propose_action` | Log-only response recommendation (no auto-containment) |
| `approve_case` | Human closing outcome (status + notes only; no containment) |
| `upsert_entity` / `link_alert_to_entity` / `link_case_to_entity` / `find_related` | SQLite entity correlation (not Neo4j) |
| `enrich_ioc` | VirusTotal lookup for ip / domain / url / hash |

## Out of scope

- Auto-containment / SOAR execution
- Neo4j, Security Onion, Hydra (Hydra breaks `sshd`)
- Public Cursor cloud reaching private LAN Wazuh (case payload + repo context only unless a self-hosted pool/tunnel exists)
- Entity correlation beyond SQLite `find_related`
