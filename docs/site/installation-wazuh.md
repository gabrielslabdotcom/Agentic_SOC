# Installation — Wazuh

Operator detail: [SETUP_GUIDE.md §3–4](../SETUP_GUIDE.md) (certs, `vm.max_map_count`, native agent).

Run on Pop via `ssh <ssh-alias>`. This lab uses **official Wazuh Docker single-node** (pin a v4.14.x tag).

```bash
ssh <ssh-alias>
mkdir -p ~
cd ~
git clone https://github.com/wazuh/wazuh-docker.git
cd wazuh-docker
git checkout v4.14.7   # or the tag in SETUP_GUIDE
cd single-node
docker compose -f generate-indexer-certs.yml run --rm generator
# then docker compose up -d  (see SETUP_GUIDE for Desktop credsStore and sysctl)
```

Install path on this lab: `$WAZUH_COMPOSE_DIR`.

## From the Mac

Open the dashboard in a browser (accept the self-signed cert):

- https://<SIEM_HOST>

Authenticate with the **lab** indexer/dashboard user. Do not publish those passwords in this write-up; they live in Pop `.env` / SETUP_GUIDE.

Smoke the APIs with placeholders:

```bash
curl -sk -u wazuh-wui:'<lab secret>' \
  -X POST 'https://<SIEM_HOST>:55000/security/user/authenticate?raw=true'

curl -sk -u admin:'<lab secret>' \
  'https://<SIEM_HOST>:9200/_cluster/health?pretty'
```

`WAZUH_API_VERIFY_SSL=false` is intentional for lab self-signed certs.

A **native** Wazuh agent on Pop (`pop-os-native`) should show in the manager. Docker-in-docker agents are optional.

Next: [Installation — Agentic SOC](installation-agentic-soc.md).
