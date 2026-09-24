# Agentic SOC

Wazuh detects. This app triages into incidents, explains them, and waits for a human to close the case. Containment stays manual.

## Four planes

```text
Wazuh indexer  →  incidents (SQLite)  →  meaning note  →  human outcome
                         ↑
                    role policy (reader / investigator / analyst)
```

### Telemetry

[`scripts/autonomy_loop.py`](scripts/autonomy_loop.py) polls the Wazuh indexer. Detection content stays in Wazuh. Lab snippets for UFW and port-scan rules live under [`deploy/wazuh/`](deploy/wazuh/). Merge them into your manager if you want the same detections, and edit syslog `allowed-ips` for your own sources.

Default poll: `AUTONOMY_MIN_LEVEL=8`. Auth failures at Wazuh level 5 are included as well (`AUTONOMY_INCLUDE_AUTH`) without lowering that minimum. Lone UFW BLOCK rule `100100` is excluded. Aggregate port-scan rules `100101` and `100102` are the ones that open work.

### Knowledge

Cases in [`src/agentic_soc/cases.py`](src/agentic_soc/cases.py) are incidents, not one row per log line.

An alert joins an **open** incident that already has the same source IP or the same user, inside `AUTONOMY_INCIDENT_HOURS` (default 6). Group only when a source IP or user is present. Rule `2501` with no source IP stays its own case. Each alert id is still unique.

`GET /tools/situation` groups open incidents by actor. The analyst UI shows that as **Happening now**. `find_related` is the SQLite entity lookup (same IP, user, hash, or domain). Host entities are excluded unless you ask for them, so every alert on one agent does not look related.

### Agent

When an incident opens, or an attached alert raises severity (`low < medium < high < critical`), Pop builds a read-only packet: the case and its brief, the attached alert count, related cases, the triggering alert, a short nearby window on the same agent, and enrichments already on the case.

That packet becomes a meaning note on the incident: what it means, evidence, related case ids, and the brief’s three next steps. The note is written even when Cursor is off.

If `AUTONOMY_CURSOR_AGENT` is on, the cloud model sees only that packet. The prompt does not include a lab API URL. The model cannot approve or execute. Pop copies a returned cloud note onto the incident. Discord’s investigation-ready follow-up fires only after that cloud note arrives.

A same-severity attach does not explain the incident and does not page Discord.

### Control

[`src/agentic_soc/policy.py`](src/agentic_soc/policy.py) is the allow-list both MCP and autonomy import. There is no login. A host on the firewall allowlist reaches the dashboard as the analyst. That is the network boundary.

| Role | Who | May |
| ---- | --- | --- |
| `reader` | lookup | List and get alerts and cases, enrich, `find_related`, situation, metrics, suppression lookup, dry-run containment plan |
| `investigator` | autonomy, MCP, meaning-note writer | Reader, plus open, update, attach, propose, entity links, noise auto-close |
| `analyst` | dashboard, [`scripts/approve_case.py`](scripts/approve_case.py) | Investigator, plus close a case, add or disable a suppression, and execute containment only when `CONTAINMENT_ENABLED` is already true |

`propose_action` records a proposal and ignores `auto_execute` for every role. A denied call returns `policy_denied`. The API maps that to HTTP 403. MCP does not expose approve or execute. Adding those tools later still fails the check inside `SocTools` for an investigator.

## What one cycle does

1. Match an analyst suppression (rule, and source IP or any source). Auto-close. No Discord, no Cursor.
2. Otherwise attach the alert to an open incident, or open a new one, and store the analyst brief.
3. On a **new** incident or a **severity rise**, write the meaning note and page Discord. A quiet attach does neither.
4. Suspicious and true-positive cases stay for a human. Informational and false-positive cases that still pass the open gate may auto-close (`AUTONOMY_AUTO_CLOSE_NOISE`) without paging.

Human outcomes **false positive**, **benign**, **informational**, and **duplicate** on the same `rule_id` and source IP skip repeats for 14 days (`AUTONOMY_FEEDBACK_SKIP`). **Confirmed compromise** does not skip. Outcomes record status and a note. They do not run UFW.

The containment card is a dry-run plan. Execute runs only when `CONTAINMENT_ENABLED=true` and an analyst confirms. Autonomy never executes it.

## Analyst UI

The dashboard is the FastAPI app in [`src/agentic_soc/api.py`](src/agentic_soc/api.py) plus [`src/agentic_soc/static/index.html`](src/agentic_soc/static/index.html).

- **Act now** — headline, actors, why, evidence, and three next steps from the brief
- **Happening now** — open incidents grouped by source IP or user
- Queue counts — open, auto-closed, human-closed, suppressions
- Rule suppressions — add or disable; confirmed compromise cannot create one
- Outcome buttons — the same closing path as Discord
- Investigation panel — meaning notes and, when the hook is on, the cloud reply

Pop’s UI banner says **LIVE Pop cases**. A workstation UI says **Mac local copy**.

## Two case databases

Live Discord and autonomy cases are `$AGENTIC_SOC_HOME/data/cases.sqlite` on the SIEM host. A git clone uses its own `data/cases.sqlite`. They are not synced.

```text
SIEM host
  ├── Wazuh (manager :55000, indexer :9200, dashboard :443)
  ├── native wazuh-agent
  ├── agentic-soc-autonomy
  ├── agentic-soc-dashboard     http://<SIEM_HOST>:8080/   (firewall allowlist)
  └── agentic-soc-discord-bot   (optional; outbound websocket, webhook fallback)

Workstation
  └── this repo                 MCP + local sqlite
      live queue: http://<SIEM_HOST>:8080/
```

| Service | URL |
| ------- | --- |
| Wazuh dashboard | `https://<SIEM_HOST>` |
| Manager API | `https://<SIEM_HOST>:55000` |
| Indexer | `https://<SIEM_HOST>:9200` |
| Analyst UI (live cases) | `http://<SIEM_HOST>:8080/` |

## Try the appliance

Someone outside this lab can run the console with Docker. The image does not include the lab host or passwords. The first browser open is the setup wizard.

The console has no login. The setup token only protects connector writes (API keys and URLs). Publish port `8080` on localhost or a trusted network.

```bash
docker compose up -d
docker compose logs -f    # first boot prints: Setup token: …
```

Open `http://<host>:8080/`. Paste the setup token. Enter your Wazuh manager API and indexer. If Wazuh is on the same machine, do not use `127.0.0.1` — that address is the container. Use the host’s LAN address or `host.docker.internal`.

An LLM (Cursor or any OpenAI-compatible chat API), VirusTotal, and Discord are optional. You still bring your own Wazuh. This app does not install a SIEM. Containment stays off.

The same **Connectors** page can change those settings later. Secrets are stored in `connectors.json` on the Compose volume and are not shown again after save.

The venv and systemd install below is the lab path. It keeps using `.env`.

## Quick start

Wazuh is installed separately. Use the official [wazuh-docker](https://github.com/wazuh/wazuh-docker) single-node guide, or any manager and indexer you already run.

### Prerequisites

- Python **3.11+**
- A reachable Wazuh manager API (`:55000`) and indexer (`:9200`)
- Optional: Discord webhook or bot token, VirusTotal key, Cursor API key (see [`.env.example`](.env.example))

### Bootstrap

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
| `cursor` | `pip install -e '.[cursor]'` | Cloud investigation from autonomy |

### Configure `.env`

1. Copy [`.env.example`](.env.example) to `.env` (bootstrap does this once).
2. Set `WAZUH_API_URL`, `WAZUH_INDEXER_URL`, and credentials for your SIEM. On the SIEM host, prefer `https://127.0.0.1:55000` and `:9200`. From another machine, use `https://<SIEM_HOST>:…`.
3. Set `CASES_DB_PATH` (default `data/cases.sqlite`).
4. Always set `.env`. Do not rely on defaults in `config.py` for URLs or passwords.
5. Never commit `.env`.

### Run locally

```bash
source .venv/bin/activate
python scripts/check_wazuh.py
uvicorn agentic_soc.api:app --host 127.0.0.1 --port 8080
# open http://127.0.0.1:8080/
pytest
```

Local `uvicorn` serves the clone’s sqlite. The live queue is the SIEM host’s UI.

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

Bind the dashboard only as needed. The API has no login, so restrict it with a firewall allowlist rather than opening `:8080` to a whole network.

### Cursor MCP (optional)

Point Cursor at the repo venv with cwd = repo root:

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

If your Cursor build does not expand `${workspaceFolder}`, substitute the absolute path to this clone. The MCP process is an investigator.

## Tool surface

Higher roles include the rows above them. Execute also requires `CONTAINMENT_ENABLED`.

| Tool | Role | Purpose |
| ---- | ---- | ------- |
| `list_agents`, `list_alerts`, `get_alert` | reader | Wazuh inventory and alerts |
| `get_case`, `list_cases`, `find_related`, `enrich_ioc` | reader | Case memory, correlation, VirusTotal |
| `situation`, `queue_metrics`, `feedback_summary` | reader | Happening now, counts, human outcomes |
| `list_suppressions`, `match_suppression`, `suppression_suggestions` | reader | Lookup only |
| `containment_plan` (dry-run) | reader | UFW deny plan, no execution |
| `open_case`, `update_case`, `attach_alert`, `propose_action` | investigator | Open work and record a proposal |
| `upsert_entity`, `link_alert_to_entity`, `link_case_to_entity` | investigator | SQLite entities |
| `approve_case` | analyst | Closing outcome (status + note) |
| `add_suppression`, `disable_suppression` | analyst | Auto-close a rule before Discord |
| `execute_containment` | analyst | HITL UFW deny when containment is enabled |

## Out of scope

- Auto-containment or SOAR execution
- API login or a second identity provider
- A tunnel from public Cursor cloud into Wazuh or the lab API
- Neo4j, Security Onion, or Hydra (Hydra breaks `sshd`)
