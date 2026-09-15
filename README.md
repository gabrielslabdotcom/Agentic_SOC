# Agentic SOC

AI-first SOC lab: **Wazuh** for detection, **agents + tools** for triage and investigation. Human-in-the-loop (HITL) only — **no auto-containment**.

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
