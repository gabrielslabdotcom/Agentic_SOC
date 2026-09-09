# Installation — Agentic SOC

Operator detail: [SETUP_GUIDE.md §5–7](../SETUP_GUIDE.md).

## Mac repo

```bash
cd /path/to/Agentic_SOC
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
cp .env.example .env
# set VIRUSTOTAL_API_KEY and Wazuh URLs/passwords in .env — never commit .env
```

Pop autonomy uses the same repo at `/home/admin/Agentic_SOC` with its **own** `.env` (Discord, Cursor key). Sync with rsync **excluding** `.env` and `data/`. Cursor extra on Pop: `pip install -e '.[cursor]'`.

## Health checks

```bash
python scripts/check_wazuh.py
python scripts/check_virustotal.py   # needs VIRUSTOTAL_API_KEY
python scripts/triage_demo.py
python scripts/eval_triage.py
```

## Cursor MCP

Project file: `.cursor/mcp.json`. Enable **agentic-soc** in Cursor Settings → MCP. It should run:

```bash
.venv/bin/python -m agentic_soc.mcp_server
```

Tools wrap `SocTools`: alerts, cases, `propose_action`, `enrich_ioc`, entity `find_related`. `propose_action` is log-only.

## Analyst UI (not the same DB)

| Cases | How |
|-------|-----|
| Live Discord / autonomy (Pop) | http://192.168.50.254:8080/ (UFW allowlisted) |
| Mac local copy | `uvicorn agentic_soc.api:app --reload --port 8080` |

The API has **no auth**. Access control is UFW (source IPs only — not the whole LAN). OpenAPI: `/docs` on whichever instance you started. Optional tunnel fallback: `./scripts/tunnel_pop_dashboard.sh` → http://127.0.0.1:8081/.

Next: [Operations](operations.md).
