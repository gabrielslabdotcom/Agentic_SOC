# Overview

Agentic SOC is a **propose-only, human-in-the-loop** lab: Wazuh detects, a local loop triages, Discord pings you, Cursor cloud writes an investigation note, and **you** Approve or Reject. It is not a fully autonomous responder.

This site is a **GitLab-style instruction set** (one page per section) for the public write-up. The operator bible with lab-only secrets remains [`docs/SETUP_GUIDE.md`](../SETUP_GUIDE.md) in the repo — **do not copy live passwords onto gabrielslab.com**.

## Architecture

```text
Pop!_OS laptop (lab SIEM host)
  ├── Wazuh Docker single-node  (manager, indexer, dashboard)
  ├── native wazuh-agent
  ├── autonomy systemd          (Discord + Cursor cloud hook)
  └── FastAPI analyst UI        (127.0.0.1:8080 — live cases)

Mac (agent / Cursor plane)
  └── Agentic_SOC               (MCP + a separate local cases.sqlite)
      SSH tunnel 8081 → Pop 8080  for LIVE Pop cases
```

Typical lab IPs (replace with yours): SIEM host `192.168.50.254`, SSH alias `soc`.

## What is live vs what is not

| Live | Not this lab |
|------|----------------|
| Detection, heuristic triage, cases, Discord HITL | Auto-containment |
| Cursor cloud investigation notes copied onto the case | Hydra (breaks `sshd`) |
| Auth L5 OR'd into the poll without lowering min-level 8 | Neo4j / SOAR / Security Onion |
| Auto-close of informational / false-positive noise | Training or fine-tuning an LLM |
| UFW deny **plans** (dry-run) | Execute UFW unless you opt in |

**Approve / Reject** record status + a note only. They do **not** run firewall rules. Containment is a separate, disabled-by-default click. See [Containment](containment.md).

## Two case databases

Pop `/home/admin/Agentic_SOC/data/cases.sqlite` is the Discord / autonomy DB. The Mac repo `data/cases.sqlite` is a **separate** copy. The dashboard banner says **LIVE Pop cases** vs **Mac local copy**. Use `./scripts/tunnel_pop_dashboard.sh` → http://127.0.0.1:8081/ for live cases.

## Credentials (public pages)

Wazuh Docker ships default accounts (`admin` / indexer, `wazuh-wui` / manager API). Put real values only in **Pop `.env`**, never in this write-up. Use placeholders:

```bash
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASSWORD=<lab secret>
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASSWORD=<lab secret>
```

Rotate before any non-lab use. Self-signed certs: `WAZUH_*_VERIFY_SSL=false` is expected.

## How to read this series

1. [Prerequisites](prerequisites.md)
2. Install: [SSH](installation-ssh.md) → [Wazuh](installation-wazuh.md) → [Agentic SOC](installation-agentic-soc.md)
3. Run: [Operations](operations.md), [Analyst workflow](workflow.md)
4. Quality and response: [Triage quality](triage-quality.md), [Cursor cloud](cursor-cloud.md), [Containment](containment.md)
5. [Troubleshooting](troubleshooting.md) · [Roadmap](roadmap.md) (including cloud)

Full command lists: [`docs/SETUP_GUIDE.md`](../SETUP_GUIDE.md).
