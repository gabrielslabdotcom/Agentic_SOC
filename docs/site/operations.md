# Operations

Operator detail: [SETUP_GUIDE.md §10–12](../SETUP_GUIDE.md).

## Wazuh stack (Pop)

```bash
ssh soc 'cd /home/admin/wazuh-docker/single-node && docker compose ps'
ssh soc 'cd /home/admin/wazuh-docker/single-node && docker compose restart'
```

## Autonomy + dashboard (systemd user units)

| Unit | Role |
|------|------|
| `agentic-soc-autonomy` | Poll Wazuh → score → open cases → Discord → Cursor cloud |
| `agentic-soc-dashboard` | FastAPI on `0.0.0.0:8080` (UFW allowlisted) |

Linger so units survive logout: `loginctl enable-linger admin` (once).

From the Mac:

```bash
python scripts/lab_status.py
ssh soc 'journalctl --user -u agentic-soc-autonomy.service -f'
```

Restart after a code sync (copy unit files, `daemon-reload`). Prefer `systemctl --user restart`. If stop hangs past ~90s, SIGKILL then start — see SETUP_GUIDE §12.3. The loop interval is 120s; a restart during sleep can still hit the stop timeout.

**Do not overwrite Pop `.env`.** Do not recreate the Discord webhook unless it was revoked.

## Live analyst UI from the Mac

Pop FastAPI binds **0.0.0.0:8080**. UFW allows TCP 8080 only from the Mac LAN IP (and optionally Kali) — **not** the whole subnet. The API has **no login**.

```bash
# Live Discord / autonomy cases
open http://192.168.50.254:8080/
# Optional fallback if LAN bind is down:
# ./scripts/tunnel_pop_dashboard.sh  →  http://127.0.0.1:8081/
```

Banner **LIVE Pop cases** vs **Mac local copy**. Mac uvicorn on `:8080` is the fixture DB only.

## Autonomy knobs (defaults)

Keep **`AUTONOMY_MIN_LEVEL=8`**. Auth failures at Wazuh level 5 are OR'd in (`AUTONOMY_INCLUDE_AUTH`). Do not lower the global floor to 5.

Also live in this lab: `AUTONOMY_FEEDBACK_SKIP`, `AUTONOMY_AUTO_CLOSE_NOISE`, `AUTONOMY_EXCLUDE_UFW_BLOCKS` (lone `100100`), `AUTONOMY_CURSOR_AGENT`, Discord. **`CONTAINMENT_ENABLED` stays false** unless you opt into HITL UFW execute.

## Code sync Mac → Pop

```bash
rsync -av --exclude '.venv' --exclude 'data/' --exclude '.env' \
  /path/to/Agentic_SOC/ soc:/home/admin/Agentic_SOC/
```

Then copy unit files if they changed, `daemon-reload`, restart units, confirm `systemctl --user is-active` for both.

Next: [Analyst workflow](workflow.md).
