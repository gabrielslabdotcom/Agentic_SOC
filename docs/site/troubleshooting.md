# Troubleshooting

Short index. Full playbooks: [SETUP_GUIDE.md §9](../SETUP_GUIDE.md) and §13.8.

| Symptom | First check |
|---------|-------------|
| Manager API refused on `:55000` | Wait 1–3 min after compose up; `docker compose ps` / manager logs |
| `docker-credential-desktop` not found | Remove `credsStore` from Pop `~/.docker/config.json` |
| Indexer yellow/red / mmap | `vm.max_map_count` (often `262144`) |
| SSL warnings | Expected (self-signed). Scripts: `WAZUH_*_VERIFY_SSL=false` |
| Agent pending | Manager address `127.0.0.1` or LAN IP; `systemctl is-active wazuh-agent` |
| Mac cannot reach Pop | Ping LAN IP, Wi-Fi, published Docker ports |
| `ModuleNotFoundError: agentic_soc` | `pip install -e .` or `PYTHONPATH=.../src` |
| `eval_triage.py` exit 1 | Tune `triage.py` or labels; `--json-out` failures list |
| Dashboard shows Mac cases | Use **http://192.168.50.254:8080/**, not Mac uvicorn 8080. Banner path should be `/home/admin/Agentic_SOC/data/cases.sqlite`. |
| Cursor SCM validation_error | GitHub App access to the repo; no-repo fallback still opens the case |
| Autonomy restart SIGKILL | Sleep interval 120s vs `TimeoutStopSec=90` — last-resort kill then start |
| Discord silent | `python scripts/check_discord.py` on Pop; do not recreate webhook unless revoked |

Do not enable Hydra on this host.
