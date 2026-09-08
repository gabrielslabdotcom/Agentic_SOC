# Agentic SOC Lab — Setup Guide

Lab reference: a **Pop!_OS laptop** runs Wazuh, autonomy, Discord notifies, Cursor cloud hook, and the localhost analyst API; a **Mac** runs Cursor MCP and a **separate** local cases DB. Historical install steps remain below; §0 “Current lab status” is what is live.

**Lab-only credentials** appear below. Do not reuse them outside this private LAN lab.

---

## 0. What you end up with

| Role | Machine | Address |
|------|---------|---------|
| SIEM host | Pop!_OS laptop | `192.168.50.254` |
| Agent / Cursor plane | Mac (this workstation) | your Mac on the same LAN |
| Optional Mac-offline LLM | Cursor cloud (kicked from Pop) | see §13 |

| Service on laptop | URL |
|-------------------|-----|
| Wazuh dashboard | https://192.168.50.254 |
| Manager API | https://192.168.50.254:55000 |
| Indexer | https://192.168.50.254:9200 |
| Analyst UI (Pop cases) | `127.0.0.1:8080` on Pop — from the Mac use `./scripts/tunnel_pop_dashboard.sh` → http://127.0.0.1:8081/ (§12.4) |

### Current lab status (2026-09)

This lab is already running. Do **not** recreate the Discord webhook or re-bootstrap Cursor cloud unless something is broken.

| Piece | Status |
|-------|--------|
| Wazuh Docker + native agent | Live on Pop (`192.168.50.254`) |
| Discord notifies | Live (`DISCORD_WEBHOOK_URL` is set on Pop) |
| Autonomy systemd | `agentic-soc-autonomy` — `AUTONOMY_MIN_LEVEL=8`, `AUTONOMY_INCLUDE_AUTH=true`, `AUTONOMY_FEEDBACK_SKIP=true`, `AUTONOMY_AUTO_CLOSE_NOISE=true`, excludes lone UFW `100100`, `AUTONOMY_CURSOR_AGENT=true` |
| Cursor cloud hook | Enabled on Pop; repo `https://github.com/gabrielslabdotcom/Agentic_SOC`. Cursor GitHub App SCM access is granted (clone works). No-repo fallback remains if SCM fails. **Do not use Hydra** — it breaks `sshd`. |
| Analyst UI for live Discord cases | FastAPI on Pop `127.0.0.1:8080` (`agentic-soc-dashboard`). From the Mac: `./scripts/tunnel_pop_dashboard.sh` → http://127.0.0.1:8081/ (banner **LIVE Pop cases**). Do not use Mac port 8080 for the tunnel. |
| Case DBs | **Two copies.** Pop `/home/admin/Agentic_SOC/data/cases.sqlite` is the live Discord/autonomy DB. Mac `data/cases.sqlite` is a separate local copy. The dashboard banner says which one you are looking at. |
| Approve / Reject | Record-only (status + note). Never containment. Discord embeds and the dashboard glossary say the same thing. |
| Live vs eval | Live `AUTONOMY_MIN_LEVEL=8` is unchanged. sshd/PAM **level 5** auth failures are OR'd in (`AUTONOMY_INCLUDE_AUTH`). Eval fixtures cover the same auth + sudo/rootkit shapes. |
| Entity correlation | SQLite `entities` + `entity_links` + `find_related`. Neo4j remains deferred. |

**Lab-only default passwords (Wazuh Docker single-node):**

| Surface | User | Password |
|---------|------|----------|
| Dashboard / Indexer | `admin` | `SecretPassword` |
| Manager API | `wazuh-wui` | `MyS3cr37P450r.*-` |

Wazuh install path on the laptop: `/home/admin/wazuh-docker/single-node`.

---

## 1. Prerequisites

### On both machines

- Same LAN (Mac can reach `192.168.50.254`)
- Docker Desktop or Docker Engine on the Pop!_OS laptop
- Python 3.11+ on the Mac

### On the Mac

- SSH client (built into macOS)
- An SSH key (this lab uses `~/.ssh/id_ed25519`)

### On the Pop!_OS laptop

- User `admin` with Docker access (prefer Docker without sudo for day-to-day)
- Enough disk for Wazuh images (~several GB)

---

## 2. SSH alias on the Mac

1. Ensure your public key is authorized on the laptop for `admin@192.168.50.254`.

2. Add an alias to `~/.ssh/config`:

```sshconfig
Host soc
  HostName 192.168.50.254
  User admin
  IdentityFile ~/.ssh/id_ed25519
  IdentitiesOnly yes
```

3. Test:

```bash
ssh -o BatchMode=yes -o ConnectTimeout=8 soc 'hostname && whoami'
```

You should see the laptop hostname and `admin` with no password prompt.

---

## 3. Deploy Wazuh on Pop!_OS (Docker single-node v4.14.x)

Run these on the laptop via `ssh soc` (or locally on the laptop).

### 3.1 Clone official Wazuh Docker repo

```bash
ssh soc
mkdir -p /home/admin
cd /home/admin
git clone https://github.com/wazuh/wazuh-docker.git
cd wazuh-docker
git checkout v4.14.7   # or the tag matching your lab docs
cd single-node
```

### 3.2 Generate certificates

Follow the upstream single-node docs for your tag. Typically:

```bash
cd /home/admin/wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
```

### 3.3 Fix Docker `credsStore: desktop` (common Mac/Desktop leftover)

If `docker pull` fails with `docker-credential-desktop` errors on Linux, edit Docker config:

```bash
# On the laptop
python3 - <<'PY'
from pathlib import Path
import json
p = Path.home() / ".docker" / "config.json"
data = json.loads(p.read_text()) if p.exists() else {}
data.pop("credsStore", None)
data.pop("credStore", None)
p.parent.mkdir(parents=True, exist_ok=True)
p.write_text(json.dumps(data, indent=2) + "\n")
print("Updated", p)
PY
```

### 3.4 `vm.max_map_count` (indexer)

Wazuh indexer needs a high `vm.max_map_count` (often `262144`). Check:

```bash
sysctl vm.max_map_count
```

If it is already high enough, do nothing. Raising it usually needs **sudo** — ask your host admin or set it once with:

```bash
# needs sudo — skip if already high enough
sudo sysctl -w vm.max_map_count=262144
```

### 3.5 Start the stack

```bash
cd /home/admin/wazuh-docker/single-node
docker compose up -d
docker compose ps
```

Expect containers similar to:

- `single-node-wazuh.manager-1` — ports `55000`, `1514`, `1515`, …
- `single-node-wazuh.indexer-1` — port `9200`
- `single-node-wazuh.dashboard-1` — host `443` → container `5601`

First boot can take several minutes while the manager API becomes ready.

### 3.6 Verify from the laptop

```bash
# Manager API token (lab-only password)
curl -sk -u wazuh-wui:'MyS3cr37P450r.*-' \
  -X POST 'https://localhost:55000/security/user/authenticate?raw=true'
echo

# Indexer health
curl -sk -u admin:SecretPassword 'https://localhost:9200/_cluster/health?pretty'

# Dashboard (expect 302 or 200)
curl -sk -o /dev/null -w '%{http_code}\n' https://localhost:443
```

### 3.7 Optional: Docker Wazuh agent (no sudo)

Native agents need package install + privileges. For a quick agent without sudo:

```bash
cd /home/admin/wazuh-docker
# Use upstream wazuh-agent compose if present, set manager IP to the laptop LAN IP
cd wazuh-agent
# Ensure WAZUH_MANAGER / WAZUH_MANAGER_SERVER points at 192.168.50.254
docker compose up -d
docker ps --filter name=wazuh.agent
```

The agent may take a few minutes to enroll and show as `active` in the manager.

Prefer the **native** agent (§3.8) for richer host telemetry. If both are enrolled, stop the Docker agent after the native one is healthy:

```bash
ssh soc 'cd /home/admin/wazuh-docker/wazuh-agent && docker compose stop'
```

### 3.8 Native Wazuh agent on Pop!_OS (4.14.x)

Install the official agent matching the manager (**4.14.7**). Needs root (`sudo`, or — in this lab — a privileged Docker `chroot` because `admin` is in the `docker` group and passwordless sudo is not enabled).

**Official apt path (when you have an interactive sudo password):**

```bash
ssh -t soc
sudo apt-get update
sudo apt-get install -y gnupg apt-transport-https curl ca-certificates
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt-get update
# Same host as the published manager ports → use 127.0.0.1
WAZUH_MANAGER="127.0.0.1" WAZUH_AGENT_NAME="pop-os-native" sudo -E apt-get install -y wazuh-agent
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
systemctl status wazuh-agent --no-pager
```

**Lab note:** this environment installed via privileged Docker chroot (docker-group equivalent of root) because `sudo -n` fails without a TTY password.

Verify from the manager API (expect a distinct agent, e.g. id `002` / `pop-os-native`, status `active`):

```bash
TOKEN=$(curl -sk -u wazuh-wui:'MyS3cr37P450r.*-' \
  -X POST 'https://192.168.50.254:55000/security/user/authenticate?raw=true')
curl -sk -H "Authorization: Bearer $TOKEN" \
  'https://192.168.50.254:55000/agents?pretty=true'
```

---

## 4. Access dashboard and API from the Mac

Open in a browser (accept the self-signed cert warning):

- Dashboard: https://192.168.50.254  
  Login: `admin` / `SecretPassword` (**lab-only**)

API smoke test from the Mac:

```bash
curl -sk -u wazuh-wui:'MyS3cr37P450r.*-' \
  -X POST 'https://192.168.50.254:55000/security/user/authenticate?raw=true'
echo

curl -sk -u admin:SecretPassword \
  'https://192.168.50.254:9200/_cluster/health?pretty'
```

`WAZUH_API_VERIFY_SSL=false` in `.env` is intentional for this lab’s self-signed certs.

---

## 5. Set up Agentic_SOC on the Mac

```bash
cd /Users/admin/Documents/Agentic_SOC

python3 -m venv .venv
source .venv/bin/activate

# Editable install (makes `agentic_soc` importable)
pip install -e .

# Lab config (already matches 192.168.50.254 defaults)
cp .env.example .env
# Edit .env: set VIRUSTOTAL_API_KEY=... (do not commit .env)
```

Edit `.env` only if your laptop IP or passwords differ. Put enrichment keys only in `.env` — never in README or this guide.

Package layout:

```text
src/agentic_soc/   # Python package (tools, API, MCP server, enrichment)
scripts/           # check_wazuh.py, check_virustotal.py, triage_demo.py, agent_triage.py
.cursor/mcp.json   # Cursor MCP wiring
docs/SETUP_GUIDE.md
```

Scripts also prepend `src/` to `sys.path`, so they work even without the editable install if you set:

```bash
export PYTHONPATH=/Users/admin/Documents/Agentic_SOC/src
```

---

## 6. Run health check and triage

With the venv active and Wazuh up:

```bash
cd /Users/admin/Documents/Agentic_SOC
source .venv/bin/activate

python scripts/check_wazuh.py
python scripts/check_virustotal.py   # needs VIRUSTOTAL_API_KEY in .env
python scripts/triage_demo.py
```

**What success looks like**

- `check_wazuh.py`: `[ok] API auth`, agents summary/list (including native `pop-os-native` if installed), indexer alerts query
- `check_virustotal.py`: `VIRUSTOTAL_API_KEY configured: True` and `[ok] VirusTotal auth OK` (never prints the key)
- `triage_demo.py`: lists agents, pulls recent alerts (or opens a warm-up case if none), writes a case to `data/cases.sqlite`, records a **proposal-only** action (no auto-containment)

### 6.1 Closed-loop triage playbook

While you generate events on the laptop (failed SSH, sudo, downloads, etc.), run:

```bash
# Score alerts, enrich public IOCs via VirusTotal, open cases for suspicious/TP
python scripts/agent_triage.py --agent-name pop-os-native --min-level 5 --max-cases 8

# Include lower-severity noise for tuning heuristics
python scripts/agent_triage.py --min-level 3 --dry-run --limit 30

# Persist a machine-readable report
python scripts/agent_triage.py --min-level 3 --json-out data/triage_report.json
```

Behavior:

1. `list_alerts` from the indexer (filter by `--min-level` / `--agent-name` / `--query`)
2. Extract IOCs from alert text (skips RFC1918 IPs unless `--include-private-ips`)
3. Optional VirusTotal `enrich_ioc` (disable with `--no-enrich`)
4. Heuristic disposition in `src/agentic_soc/triage.py` (`true_positive` / `suspicious` / `false_positive` / `informational`)
5. Shared `should_open_case()` gate (same logic as `scripts/eval_triage.py`): skips CIS/SCA noise, lone UFW `100100`, and agent queue-full / capacity alerts; opens for auth failures and port-scan aggregates
6. Opens SQLite cases for gated findings, sets disposition, `propose_action` (**never** auto-contains)
7. Skips duplicate `alert_id`s already in the case store

Useful flags: `--dry-run`, `--max-cases`, `--no-enrich`, `--json-out`.

Human approval stub (after a case is opened):

```bash
python scripts/approve_case.py --case-id N --approve --note "ok to document"
python scripts/approve_case.py --case-id N --reject --note "noise"
```

Two FastAPI + **Agentic SOC Analyst** dashboards can run; they do **not** share a database:

| Where | Cases DB | How to open |
|-------|----------|-------------|
| **Pop (live Discord / autonomy cases)** | `/home/admin/Agentic_SOC/data/cases.sqlite` | systemd `agentic-soc-dashboard` on `127.0.0.1:8080`. From the Mac: `./scripts/tunnel_pop_dashboard.sh` then http://127.0.0.1:8081/ |
| **Mac (local copy)** | this repo’s `data/cases.sqlite` | `uvicorn agentic_soc.api:app --reload --port 8080` on the Mac. Fine to keep running; it is a **different** DB. |

Preferred path for cases Discord opens: **Pop API + SSH tunnel** (no unauthenticated LAN bind). See §12.4.

```bash
# Mac-local dashboard only (this Mac's cases.sqlite — not the Discord/autonomy DB)
cd /Users/admin/Documents/Agentic_SOC
source .venv/bin/activate
uvicorn agentic_soc.api:app --reload --port 8080
```

| URL (whichever API you pointed the browser at) | Purpose |
|-----|---------|
| http://127.0.0.1:8080/ or `/dashboard/` | Analyst UI: list/filter cases, related cases, alert context, Approve / Reject, optional IOC enrich |
| http://127.0.0.1:8080/docs | OpenAPI for tool endpoints |

Useful endpoints (same lab-safe semantics as CLI/MCP):

- `GET /tools/list_cases?status=open|approved|rejected|pending` (`pending` → open)
- `GET /tools/get_case/{case_id}`
- `POST /tools/approve_case/{case_id}` body `{"approved": true|false, "note": "..."}` — **no containment**
- `GET /tools/find_related?case_id=` — other cases sharing IP / hash / user / domain
- `POST /tools/upsert_entity`, `POST /tools/link_alert_to_entity`, `POST /tools/link_case_to_entity`
- `GET /tools/get_alert/{alert_id}`, `GET /tools/enrich_ioc?ioc=...`
- `GET /tools/ui_config` — Wazuh dashboard link + cases DB path for the UI

**Approve / Reject** (dashboard glossary + Discord embed field “What Approve / Reject records”):

- **Approve** — accept the triage (disposition + recommended action). Status becomes `approved`; a note is stored. **No containment.**
- **Reject** — noise, duplicate, or wrong proposal. Status becomes `rejected`; a note is stored. **Also no containment.**

Optional: set `WAZUH_DASHBOARD_URL` in `.env` (default `https://192.168.50.254`) for the “Open Wazuh dashboard” link.

---

## 7. Cursor MCP (agentic_soc.tools)

This repo ships a stdio MCP server that wraps `SocTools` (`list_agents`, `list_alerts`, `get_alert`, cases, `propose_action`, `enrich_ioc`, `upsert_entity`, `link_alert_to_entity`, `link_case_to_entity`, `find_related`).

### 7.1 Install deps

```bash
cd /Users/admin/Documents/Agentic_SOC
source .venv/bin/activate
pip install -e .
```

### 7.2 Project MCP config

File: **`.cursor/mcp.json`** (paste-equivalent):

```json
{
  "mcpServers": {
    "agentic-soc": {
      "command": "/Users/admin/Documents/Agentic_SOC/.venv/bin/python",
      "args": ["-m", "agentic_soc.mcp_server"],
      "cwd": "/Users/admin/Documents/Agentic_SOC",
      "env": {
        "PYTHONPATH": "/Users/admin/Documents/Agentic_SOC/src"
      }
    }
  }
}
```

Do **not** put `VIRUSTOTAL_API_KEY` or Wazuh passwords in `mcp.json` — the server loads them from the repo `.env`.

### 7.3 Enable in Cursor

1. Open this folder as the workspace.
2. **Cursor Settings → MCP** (or Features → MCP).
3. Confirm **agentic-soc** appears and toggle it **on** / reload if needed.
4. In chat, tools such as `list_agents` and `enrich_ioc` should be available.

Manual smoke test from a terminal:

```bash
cd /Users/admin/Documents/Agentic_SOC
source .venv/bin/activate
python -c "from agentic_soc.mcp_server import mcp; print('server', mcp.name)"
```

---

## 8. Optional next steps

1. Generate interesting host events, then re-run `scripts/agent_triage.py` (full workflow in **§11**).
2. **Port scans (nmap-style)** — see §8.1 below (UFW + custom Wazuh rules).
3. **Human approval** — use `scripts/approve_case.py` on proposed actions; still no auto-containment (§11.4).
4. **Triage eval** — `python scripts/eval_triage.py` against `evals/labeled_alerts.json` (§11.3).
5. **SQLite entity correlation** is implemented (`entities` / `entity_links` / `find_related` — see §14). Graduate to Neo4j only if multi-hop graph queries, entity volume, or relationship types outgrow SQLite. Those criteria remain deferred.
6. **AbuseIPDB** — set `ABUSEIPDB_API_KEY` in `.env` when you add that client.
7. Live autonomy stays at **min-level 8**. Auth L5 is ingested via an OR query (`AUTONOMY_INCLUDE_AUTH`); do **not** lower `AUTONOMY_MIN_LEVEL`. Reject on the same `rule_id`+source IP skips repeats. Informational/FP may auto-close without Discord. New HITL cases get a **UFW deny dry-run plan** on the case; Execute requires `CONTAINMENT_ENABLED=true` (not set by default). **No auto-containment.**
8. Reference only: `/home/admin/Blue-Team-MCP` on the laptop (optional host tools; not required for this scaffold).

### 8.1 Seeing nmap / port-scan alerts

A host Wazuh agent does **not** see raw packets. Port scans become alerts when:

1. **UFW** is enabled with logging (`logging high`) and **default deny incoming**
2. Allowed services only (SSH `22`, Wazuh `1514/1515/55000`, indexer `9200`, dashboard `443/5601`)
3. Agent monitors `/var/log/ufw.log` (and/or journald)
4. Manager local rules fire on `[UFW BLOCK]` bursts (`100100` / `100101` / `100102`)

**Generate lab scan traffic from the Mac** (no nmap required):

```bash
cd /Users/admin/Documents/Agentic_SOC
source .venv/bin/activate
python scripts/generate_portscan_lab.py --host 192.168.50.254
```

Or with nmap, from another LAN host:

```bash
nmap -Pn -T4 -p 1-100,3306,3389,8080 192.168.50.254
```

Within ~30s you should see alerts such as:

- `UFW firewall block event.` (rule `100100`, level 5)
- `Possible port scan (lab): ...` (rule `100102`, level 8)
- `Possible port scan: multiple UFW blocks from same source.` (rule `100101`, level 10)

**Triage behavior:** aggregate rules `100101`/`100102` open cases as suspicious/true_positive. Lone `100100` floods are demoted to informational and **skipped** so you do not open dozens of duplicate low-value cases.

**Important:** Do **not** `ufw allow from 192.168.50.0/24` — that would allow closed ports and suppress BLOCK logs. After `ufw reload`, restart Docker if published ports (`9200`/`55000`) stop answering on the LAN (`sudo systemctl restart docker` then `docker compose up -d` in `/home/admin/wazuh-docker/single-node`).

---

## 9. Troubleshooting

### Manager API not ready / connection refused on `:55000`

- Wait 1–3 minutes after `docker compose up -d`.
- Check: `ssh soc 'cd /home/admin/wazuh-docker/single-node && docker compose ps && docker compose logs --tail=80 wazuh.manager'`

### `docker-credential-desktop: executable file not found`

- Remove `credsStore` / `credStore` from `~/.docker/config.json` on the **laptop** (see §3.3).

### Indexer fails / yellow-red cluster / `max virtual memory areas`

- Confirm `sysctl vm.max_map_count` is high enough (often `262144`). Needs sudo to change.

### SSL / certificate warnings

- Expected with self-signed lab certs. Browser: proceed after warning. Scripts: `WAZUH_*_VERIFY_SSL=false`.

### Agent not listed or `pending`

- Confirm manager address in agent config is `127.0.0.1` (same host) or `192.168.50.254`.
- Native agent logs: `ssh soc 'docker run --rm --privileged --pid=host -v /:/host ubuntu:24.04 chroot /host tail -80 /var/ossec/logs/ossec.log'`
- Docker agent logs: `ssh soc 'docker logs wazuh-agent-wazuh.agent-1 --tail=100'`
- Authd / enrollment can take a few minutes.
- Service: `ssh soc 'systemctl is-active wazuh-agent'`

### Mac cannot reach laptop

- Ping `192.168.50.254`, confirm Wi‑Fi/LAN, firewall, and that Docker ports are published on `0.0.0.0`.

### `ModuleNotFoundError: agentic_soc`

```bash
cd /Users/admin/Documents/Agentic_SOC
source .venv/bin/activate
pip install -e .
# or:
export PYTHONPATH=/Users/admin/Documents/Agentic_SOC/src
```

### Eval harness fails (`scripts/eval_triage.py` exit 1)

- Heuristics live in `src/agentic_soc/triage.py`; labels in `evals/labeled_alerts.json`.
- Re-run with `--json-out data/eval_report.json` and inspect the `failures` list.
- Tune labels or heuristics, then re-run until disposition + open-case accuracy meet thresholds.

---

## 10. Day-2 useful commands

```bash
# Laptop stack status
ssh soc 'cd /home/admin/wazuh-docker/single-node && docker compose ps'

# Restart stack
ssh soc 'cd /home/admin/wazuh-docker/single-node && docker compose restart'

# Stop stack
ssh soc 'cd /home/admin/wazuh-docker/single-node && docker compose down'
```

Keep passwords lab-only; rotate before any shared or production use.

---

## 11. End-user workflow: generate → triage → eval → approve

Anyone with this repo + a working lab (or dry-run against fixtures) can follow these steps.

### 11.1 Generate events (laptop / LAN)

**Port scan (preferred for UFW rules):**

```bash
cd /Users/admin/Documents/Agentic_SOC
source .venv/bin/activate
python scripts/generate_portscan_lab.py --host 192.168.50.254
```

Wait ~15–30 seconds for Wazuh to index alerts.

**Auth failures (optional):** from another host, attempt a few bad SSH logins to the laptop (do not lock yourself out). Or use existing indexer history.

### 11.2 Run triage

```bash
cd /Users/admin/Documents/Agentic_SOC
source .venv/bin/activate

# Preview scoring without writing cases
python scripts/agent_triage.py --agent-name pop-os-native --min-level 5 --dry-run --limit 30

# Open cases for suspicious / true_positive (skips CIS noise, lone 100100, agent queue-full)
python scripts/agent_triage.py --agent-name pop-os-native --min-level 5 --max-cases 8 \
  --json-out data/triage_report.json
```

What to expect:

| Alert type | Disposition | Case opened? |
|------------|-------------|--------------|
| Port-scan aggregate `100101` / `100102` | suspicious or true_positive | yes |
| Auth failure / missed password | suspicious | yes |
| CIS / SCA compliance | informational or false_positive | no (under threshold) |
| Lone UFW BLOCK `100100` | informational | no (prefer aggregates) |
| Agent event queue full / events may be lost | informational or false_positive | no (flood side-effect) |

Cases land in `data/cases.sqlite`. Each opened case gets a `propose_action` note — **containment is never executed**.

### 11.3 Run the eval harness

```bash
python scripts/eval_triage.py
# optional detail:
python scripts/eval_triage.py --json-out data/eval_report.json
# human Approve / Reject skip keys (rule_id + source IP):
python scripts/eval_feedback.py
```

Interpreting scores:

- **Disposition accuracy** — fraction of labeled alerts whose predicted disposition is in the allowed set
- **Open-case accuracy** — fraction where “would open a case?” matches the label
- Default floors are in `evals/labeled_alerts.json` (`min_disposition_accuracy` ≈ 80%, `min_open_case_accuracy` ≈ 85%)
- Exit code `0` = PASS; `1` = below threshold; inspect printed failures / confusion matrix

Unit tests (optional):

```bash
pip install pytest
pytest tests/ -q
```

### 11.4 Approve or reject a proposed action

List recent cases (MCP `list_cases`, HTTP API, dashboard, or Python):

```bash
python -c "from agentic_soc.tools import SocTools; import json; print(json.dumps(SocTools().list_cases(limit=10), indent=2))"
```

**Web dashboard** (preferred for interactive review of **live Discord cases**):

```bash
# Mac → Pop tunnel (Pop FastAPI is bound to 127.0.0.1:8080; local 8081 avoids Mac uvicorn)
./scripts/tunnel_pop_dashboard.sh
# then open http://127.0.0.1:8081/dashboard/
```

A Mac-local `uvicorn --port 8080` is fine for this repo’s `data/cases.sqlite`; it will **not** show cases Discord just opened. Use the 8081 tunnel for live cases. See §12.4.

Approve / Reject in the UI calls `POST /tools/approve_case/{id}` (same `resolve_proposal` path as the CLI).

**What those decisions record (lab):**

- **Approve** — you accept the triage (disposition + recommended action). Case status becomes `approved`; a note is stored. **No containment runs.**
- **Reject** — you treat the case as noise, a duplicate, or a wrong proposal. Status becomes `rejected`; a note is stored. **Also no containment.**

CLI approve / reject (updates status + notes only):

```bash
# Approve
python scripts/approve_case.py --case-id 12 --approve --note "Confirmed lab port-scan; document only"

# Reject
python scripts/approve_case.py --case-id 12 --reject --note "CIS noise / duplicate"
```

Status becomes `approved` or `rejected`. **No firewall, agent kill, or other containment runs** — this is an approval stub for the propose_action path.

---

## 12. Autonomy service on Pop!_OS + Discord

**Already live.** Pop `agentic-soc-autonomy` polls Wazuh, opens cases in `/home/admin/Agentic_SOC/data/cases.sqlite`, pings Discord, and kicks the Cursor cloud hook (`AUTONOMY_CURSOR_AGENT=true`). **Containment is never auto-executed.**

Do **not** recreate the Discord webhook or overwrite `/home/admin/Agentic_SOC/.env`.

### 12.1 Discord (configured)

The incoming webhook is already in Pop `.env` as `DISCORD_WEBHOOK_URL`. New cases post an embed with triage reasons, rule id/level, IOCs, VT summary, log snippet, CLI snippets, and a **What Approve / Reject records** field (status + note only; no containment).

Smoke test only if notifies stop:

```bash
ssh soc 'cd /home/admin/Agentic_SOC && source .venv/bin/activate && python scripts/check_discord.py'
```

Replacement playbook (only if the webhook was revoked): Discord channel → Integrations → Webhooks → new URL → edit `DISCORD_WEBHOOK_URL` in Pop `.env` (never commit) → restart autonomy (§12.3).

### 12.2 Service layout (already installed)

Code lives at `/home/admin/Agentic_SOC`. User units:

| Unit | Role |
|------|------|
| `~/.config/systemd/user/agentic-soc-autonomy.service` | Triage loop + Discord + Cursor cloud |
| `~/.config/systemd/user/agentic-soc-dashboard.service` | FastAPI analyst UI on `127.0.0.1:8080` (§12.4) |

Autonomy knobs (unit file + `.env`): `AUTONOMY_INTERVAL=120`, **`AUTONOMY_MIN_LEVEL=8`**, `AUTONOMY_INCLUDE_AUTH=true` (OR in sshd/PAM auth at level 5; do **not** lower min-level), `AUTONOMY_FEEDBACK_SKIP=true` (skip same `rule_id`+source IP after a reject), `AUTONOMY_AUTO_CLOSE_NOISE=true` (auto-close informational/FP without Discord; suspicious stays HITL), `AUTONOMY_EXCLUDE_UFW_BLOCKS=true` (skips lone rule `100100`), `AUTONOMY_MAX_CASES`, `AUTONOMY_DISCORD=true`, **`AUTONOMY_CURSOR_AGENT=true`**.

Linger (already needed once so the user service survives logout):

```bash
loginctl enable-linger admin
```

### 12.3 Day-2 ops

From the Mac:

```bash
python scripts/lab_status.py
ssh soc 'journalctl --user -u agentic-soc-autonomy.service -f'
```

**Restart (preferred):** the unit uses `TimeoutStopSec=90` and the loop stops **between alerts** on SIGTERM. After copying a refreshed unit file:

```bash
ssh soc 'cp /home/admin/Agentic_SOC/deploy/agentic-soc-autonomy.service ~/.config/systemd/user/ && systemctl --user daemon-reload'
ssh soc 'systemctl --user restart agentic-soc-autonomy.service'
```

**Last resort** if restart still hangs past ~90s:

```bash
ssh soc 'systemctl --user kill -s SIGKILL agentic-soc-autonomy.service; systemctl --user start agentic-soc-autonomy.service'
# Same pattern for the dashboard unit if uvicorn does not die (TimeoutStopSec=30).
```

Clean stop (when it actually exits):

```bash
ssh soc 'systemctl --user stop agentic-soc-autonomy.service'
```

When Discord fires: review the embed, then **Approve / Reject** from the Pop dashboard (§12.4) or `approve_case.py` against the **Pop** DB (or via the tunneled API). Mac `data/cases.sqlite` is a separate copy.

### 12.4 Analyst dashboard on Pop (live cases)

The dashboard service binds **127.0.0.1:8080** only (unauthenticated lab API — do not expose on the LAN). Prefer local port **8081** on the Mac so a local uvicorn on 8080 cannot shadow live cases. The UI banner reads **LIVE Pop cases** vs **Mac local copy**.

```bash
# From the Mac — preferred (leaves 8080 free)
./scripts/tunnel_pop_dashboard.sh
# Browser: http://127.0.0.1:8081/  or  http://127.0.0.1:8081/dashboard/
```

Equivalent: `ssh -N -L 8081:127.0.0.1:8080 soc`.

Install / refresh the user unit (does **not** touch `.env`):

```bash
ssh soc
mkdir -p ~/.config/systemd/user
cp /home/admin/Agentic_SOC/deploy/agentic-soc-dashboard.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now agentic-soc-dashboard.service
# if enable/restart hangs past TimeoutStopSec=30: kill then start
systemctl --user kill -s SIGKILL agentic-soc-dashboard.service
systemctl --user start agentic-soc-dashboard.service
systemctl --user status agentic-soc-dashboard.service
```

Optional UFW allow from the Mac LAN IP only if you already have that pattern and accept an unauthenticated API on the LAN. Prefer the SSH tunnel so the API stays on localhost.

```bash
# Not the default — only if you bind 0.0.0.0 and lock source IP
# sudo ufw allow from <MAC_LAN_IP> to any port 8080 proto tcp
```

## 13. Mac-offline LLM: Cursor cloud investigation (propose-only)

**Already enabled on Pop** (`AUTONOMY_CURSOR_AGENT=true`). After each case open (same place Discord is notified), `autonomy_loop` kicks a Cursor SDK **cloud** agent. Repo: `https://github.com/gabrielslabdotcom/Agentic_SOC`. The Cursor GitHub App can see that repo; the VM **clones successfully**. This is **not** Automations-first, **not** Neo4j, **not Hydra** (Hydra breaks `sshd` on this lab — do not enable it), and **never** auto-containment.

Do **not** re-paste `CURSOR_API_KEY` or overwrite Pop `.env` unless the key was rotated.

### 13.1 Architecture

```mermaid
sequenceDiagram
  participant Wazuh as Wazuh on Pop
  participant Loop as autonomy_loop (systemd)
  participant Discord as Discord webhook
  participant SDK as Cursor SDK cloud VM

  Loop->>Wazuh: poll / score / open case
  Loop->>Discord: notify case opened
  Loop-->>SDK: Agent.prompt (background thread)
  Note over SDK: investigate from case payload + repo playbooks
  SDK-->>Loop: final reply (SDK result)
  Loop->>Loop: append note to SQLite case
  Loop->>Discord: investigation note ready
  Note over Loop,Discord: human still approves via dashboard / approve_case.py
```

| Role | Who | What |
|------|-----|------|
| Detection + case open | Pop `autonomy_loop` | Poll Wazuh, score, open SQLite case, `propose_action` only |
| Human ping | Discord | Embed with context + approve/reject CLI snippets |
| LLM investigation | Cursor **cloud** agent | Propose-only final reply; Pop copies it onto the case |
| Investigation ping | Discord | Follow-up embed when the note lands |
| Approval | Human | `approve_case.py` / dashboard — still required; no containment |

**Mac-offline behavior:** the Mac does not need to be online. Pop calls the Cursor API with `CURSOR_API_KEY`; the agent runs on a Cursor-hosted VM (or your self-hosted pool). Discord still fires from Pop.

### 13.2 LAN caveat (important)

Public Cursor cloud VMs **cannot** reach `192.168.50.254` (Wazuh / Pop FastAPI on the lab LAN) without extra networking.

| Option | Live Wazuh from agent? | Case note on SQLite? | When to use |
|--------|------------------------|----------------------|-------------|
| **A. Public cloud (this lab)** | No | **Yes** — Pop copies `Agent.prompt` final reply onto the case. No LAN tunnel required. | Default |
| **B. Tunnel** | Possible if tunnel includes Wazuh ports | Also possible via `AGENTIC_SOC_API_URL` (optional extra) | Want the VM itself to call Pop APIs |
| **C. Self-hosted pool on Pop** | Yes (worker is on LAN) | Yes — local persist still works; optional `AGENTIC_SOC_API_URL=http://127.0.0.1:8080` | Enterprise self-hosted workers |

**This lab’s path:** public cloud + `CURSOR_AGENT_REPO=https://github.com/gabrielslabdotcom/Agentic_SOC`. Pop persists the investigation note locally, then Discord pings “note ready”. Analysts read it on the tunneled dashboard (§12.4) before Approve / Reject. HTTP write-back from the VM is optional, not required.

### 13.3 Status on Pop (already installed)

`pip install -e '.[cursor]'` is done. `.env` already has `AUTONOMY_CURSOR_AGENT=true`, `CURSOR_API_KEY`, and `CURSOR_AGENT_REPO=https://github.com/gabrielslabdotcom/Agentic_SOC`. Do not `cat > .env`.

Dry-run (prints the investigation prompt, no SDK call):

```bash
ssh soc 'cd /home/admin/Agentic_SOC && source .venv/bin/activate && python scripts/autonomy_loop.py --once --cursor-dry-run --no-discord'
```

If you must refresh the unit file after a code sync, copy + daemon-reload, then **kill + start** if restart hangs (§12.3). `.env` still drives `cursor_agent=True`.

### 13.4 Env reference

| Variable | This lab | Purpose |
|----------|----------|---------|
| `AUTONOMY_CURSOR_AGENT` | `true` on Pop | Enable cloud investigation after case open |
| `CURSOR_API_KEY` | set on Pop (never commit) | User or service-account key ([Integrations](https://cursor.com/dashboard/integrations)) |
| `CURSOR_AGENT_MODEL` | `composer-2.5` | SDK model id |
| `CURSOR_AGENT_REPO` | `https://github.com/gabrielslabdotcom/Agentic_SOC` | SCM URL cloned into the cloud VM |
| `CURSOR_AGENT_STARTING_REF` | `main` | Branch / ref for the clone |
| `CURSOR_AGENT_NOREPO_FALLBACK` | `true` | If SCM fails, retry no-repo (case JSON only) |
| `AGENTIC_SOC_API_URL` | empty (optional) | Unused for Phase B persist. Optional extra if the cloud VM should PATCH the case itself |
| `CURSOR_CLOUD_POOL` | empty | Self-hosted pool name (`CloudAgentOptions.env type=pool`) |

CLI mirrors: `--cursor-agent` / `--no-cursor-agent`, `--cursor-dry-run`.

### 13.5 FastAPI binding (127.0.0.1 vs LAN)

The analyst API on Pop is the **systemd user unit** `agentic-soc-dashboard` (see §12.4): `uvicorn` on **127.0.0.1:8080**. That is the default. Do not bind `0.0.0.0` unless you also lock UFW to a single Mac IP — the API has **no auth**.

For a self-hosted pool worker on Pop, `AGENTIC_SOC_API_URL=http://127.0.0.1:8080` is enough (worker is local). Analysts on the Mac use the SSH tunnel, not a LAN bind.

### 13.6 Security notes

- Store `CURSOR_API_KEY` only in Pop `.env` (and optionally Mac `.env` for local experiments). Never commit it.
- Cloud agent is instructed to **propose only** — no containment, no approve/reject.
- SDK/network errors are logged as warnings; `autonomy_loop` continues (fail soft).
- Discord and Cursor cloud are independent: Discord can stay on while Cursor is off, and vice versa.
- **Do not use Cursor Hydra** on this lab host. Hydra interferes with `sshd` and can lock you out of `ssh soc`.

### 13.7 Sync code from Mac → Pop

```bash
# From the Mac repo root — never include .env or data/
rsync -av --exclude '.venv' --exclude 'data/' --exclude '.env' \
  /Users/admin/Documents/Agentic_SOC/ soc:/home/admin/Agentic_SOC/

ssh soc 'cd /home/admin/Agentic_SOC && source .venv/bin/activate && pip install -e ".[cursor]"'
# Then kill+start units if restart hangs — see §12.3
```

Do not overwrite Pop `.env` during sync.

### 13.8 Troubleshooting: SCM / GitHub access

**This lab:** the Cursor GitHub App was granted access to `gabrielslabdotcom/Agentic_SOC`; cloud agents **clone the repo**. Keep this section if SCM regresses.

Autonomy may log:

```text
cursor cloud investigation failed case=N: [validation_error] The SCM
integration does not have access to repository USER/Agentic_SOC to
verify branch existence.
```

That means the **Cursor GitHub App** (not your personal `git` login) cannot see the repo. Discord/case open still succeeded. The hook then retries a **no-repo** cloud agent (case JSON + prompt only; no clone) unless `CURSOR_AGENT_NOREPO_FALLBACK=false`.

**Fix (so the VM can clone playbooks again):**

1. Confirm `https://github.com/gabrielslabdotcom/Agentic_SOC` exists and `main` is pushed.
2. In the **same Cursor account** that minted `CURSOR_API_KEY`: [Integrations](https://cursor.com/dashboard?tab=integrations) → connect **GitHub**.
3. On GitHub: [Applications → Cursor](https://github.com/settings/installations) → repository access → include `gabrielslabdotcom/Agentic_SOC`.
4. If it still fails: uninstall the Cursor GitHub App, **Disconnect** GitHub in the Cursor dashboard, reconnect and reinstall, then re-add the repo.
5. Re-run a lab port-scan (or wait for the next case). After access was granted, the clone succeeded.

---

## 14. SQLite entity correlation (not Neo4j)

Cases on a given API’s `CASES_DB_PATH` also store **entities** and **entity_links** in the same SQLite file.

| Table | Role |
|-------|------|
| `entities` | `entity_type` + `value` — `ip`, `user`, `host`, `hash`, `domain` |
| `entity_links` | `entity_id` ↔ `alert_id` and/or `case_id` |

Tools (SocTools, FastAPI, MCP):

- `upsert_entity(entity_type, value)`
- `link_alert_to_entity` / `link_case_to_entity`
- `find_related(case_id=…)` — other cases that share IP / hash / user / domain

**How `find_related` works:** resolve seed entities from `case_id`, `alert_id`, `entity_id`, or `entity_type`+`value`. Walk links to other cases. From a case/alert seed, **`host` is not followed** (otherwise every `pop-os-native` case would look related). Pass `include_hosts=true` or query `entity_type=host` explicitly. Shared entities are returned on each related case as `matched_entities`.

Autonomy calls `correlate_alert` on case open: `extract_source_ip`, agent host, optional user, and `extract_iocs` are upserted and linked. A later nmap from the same Kali IP therefore shows **Related cases** on the analyst UI.

**Neo4j graduation criteria (deferred):** multi-hop graph queries, entity volume, or relationship types SQLite cannot express cleanly. Do not add Neo4j until those are actually needed.
