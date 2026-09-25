# Host isolation active-response scripts

These scripts run **on the endpoint**, triggered by the Wazuh manager API. They are not wired to any alert rule. Agentic SOC sends the command only after `HOST_ISOLATION_ENABLED=true` and an analyst confirm.

`pop-os-native` (the SIEM host) must not get these scripts applied as an isolation target. The app refuses that agent name even if the scripts are present.

## 1. Config on every agent you might isolate

Copy [`isolation.conf.example`](isolation.conf.example) and set:

- `WAZUH_MANAGER_IP` — manager address the agent already uses (TCP 1514/1515 must stay open)
- `ALLOWED_MGMT_IPS` — analyst or jump-box addresses that may still SSH (Linux) or RDP/SSH (Windows)

Linux path: `/var/ossec/etc/isolation.conf`  
Windows path: `C:\Program Files (x86)\ossec-agent\isolation.conf`

If `WAZUH_MANAGER_IP` is missing, the script exits and does not change the firewall.

## 2. Linux agent

```bash
sudo cp linux/network-isolation.sh linux/network-deisolation.sh /var/ossec/active-response/bin/
sudo chown root:wazuh /var/ossec/active-response/bin/network-isolation.sh /var/ossec/active-response/bin/network-deisolation.sh
sudo chmod 750 /var/ossec/active-response/bin/network-isolation.sh /var/ossec/active-response/bin/network-deisolation.sh
```

`iptables` (or `iptables-nft`) must be on `PATH`. IPv6 is dropped except loopback so it cannot bypass the IPv4 rules.

## 3. Windows agent

Copy into `C:\Program Files (x86)\ossec-agent\active-response\bin\`:

- `network-isolation.cmd`
- `network-isolation.ps1`
- `network-deisolation.cmd`
- `network-deisolation.ps1`

Wazuh runs the `.exe` launcher, which calls the matching PowerShell script. Build it on the endpoint (the `.cmd` files are only a manual fallback):

```bat
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /out:"C:\Program Files (x86)\ossec-agent\active-response\bin\network-isolation.exe" ar-launcher.cs
copy /Y "C:\Program Files (x86)\ossec-agent\active-response\bin\network-isolation.exe" "C:\Program Files (x86)\ossec-agent\active-response\bin\network-deisolation.exe"
```

Copy `network-isolation.ps1` and `network-deisolation.ps1` into that same `bin` directory. The first isolate saves current firewall-profile defaults to `agentic-isolation.state` next to the agent install and restores them on de-isolate.

## 4. Manager

Merge [`ossec-ar-snippet.xml`](ossec-ar-snippet.xml) into the manager `ossec.conf`. Restart the manager.

Do **not** bind these commands to a real rule id or level. The snippet's `<active-response>` entries use `rules_id` `999999` only so Wazuh writes them into `ar.conf`.

The API user needs RBAC `active-response:command` on the target agent ids.

Command names:

| Agent OS | Isolate | De-isolate |
| --- | --- | --- |
| Linux | `network-isolation0` | `network-deisolation0` |
| Windows | `network-isolation-win0` | `network-deisolation-win0` |

Those names come from `ar.conf` (a `0` suffix on the `<command>` name). The `<active-response>` blocks in the snippet use `rules_id` `999999`, which does not exist, so alerts do not auto-run them. The blocks exist so the manager publishes the commands.

Smoke test (replace the agent id; this **does** change that host's firewall):

```bash
TOKEN=$(curl -sk -u "$WAZUH_API_USER:$WAZUH_API_PASSWORD" \
  "https://127.0.0.1:55000/security/user/authenticate?raw=true" | tr -d '"')

curl -sk -X PUT "https://127.0.0.1:55000/active-response?agents_list=00X" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"command":"network-isolation"}'
```

De-isolate with `network-deisolation` (or the `-win` names on Windows). Confirm the agent returns to `active` in the manager before leaving the host.
