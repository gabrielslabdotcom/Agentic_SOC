# Roadmap

Public build plan for this lab. Not a dump of chat history. Nothing here trains or fine-tunes an LLM.

## Where we are

Detection → heuristic triage → HITL Discord/dashboard → Cursor investigation notes → evals + Reject skip keys → auto-close noise → bulk Approve/Reject → UFW **plans** (Execute off).

You improve the **baseline** by using the queue and encoding misses into `evals/labeled_alerts.json` + `triage.py`, not by standing up a training pipeline.

## Near (lab, still HITL)

- Grow labeled evals from live misses; run `eval_triage.py` and `eval_feedback.py` against **Pop** `cases.sqlite`
- Optional HITL UFW Execute: `CONTAINMENT_ENABLED=true` plus `sudo -n ufw` — still a separate click, never Approve, never the loop
- Autonomy SIGTERM vs 120s sleep (`TimeoutStopSec=90`) so routine restarts do not SIGKILL
- Optional: pass short Approve/Reject *summaries* into the Cursor investigation prompt (still not model training)

## Mid (productize the lab)

- API auth before the analyst UI ever leaves localhost
- AbuseIPDB client when `ABUSEIPDB_API_KEY` exists
- Keep SQLite `find_related`. Neo4j, SOAR, Security Onion, and Hydra stay deferred
- Do not lower `AUTONOMY_MIN_LEVEL` to 5

## Cloud (later — do not lift-and-shift the LAN SIEM)

```text
Now:  Wazuh + autonomy + cases on Pop LAN
      Cursor investigation already on Cursor cloud VMs
      Docs / write-up → gabrielslab.com (this markdown kit)

Not:  unauthenticated FastAPI or indexer on the public internet
Not:  autonomy on a public PaaS next to the blog (it must sit by the indexer)
```

**Already cloud:** Cursor investigation. Those VMs cannot reach `192.168.50.254`; Pop copies notes back. That split stays.

**Reasonable sequence:**

1. Publish this instruction set on [gabrielslab.com Write-ups](https://gabrielslab.com/write-ups) (placeholders only — no lab passwords).
2. Optional small VPS for a **read-only** case UI **with authentication** (or stay on SSH tunnel forever).
3. Only then a **dedicated** cloud Wazuh/SIEM node in a private VPC — new credentials, no Docker default passwords, not this laptop. Autonomy runs in that VPC next to the indexer.

Auto-containment (loop inserts UFW with no human) remains after HITL execute is trusted in the lab, not as a cloud day-one feature.

## Drop-in for gabrielslab.com

These files are markdown with the nav in [`nav.yaml`](nav.yaml). After the site repo is available: add a Write-ups listing (**Agentic SOC Lab — Wazuh, HITL autonomy, Cursor cloud**, tags AI / DFIR) and either nested routes `/write-ups/agentic-soc/...` or a hub post that links these pages. Match existing post front matter when that repo is in hand.
