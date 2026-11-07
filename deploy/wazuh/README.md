# Wazuh lab deploy snippets

Merge these into the live manager on the SIEM host (`wazuh-docker` single-node). This repo does not install Wazuh.

**Expected stack version:** 4.14.10 (manager, indexer, dashboard, docker agent). The native SIEM-host agent should match. Windows agent upgrades and Sysmon are deferred.

| Path | Purpose |
| ---- | ------- |
| `local_rules.xml` / `local_decoder.xml` | UFW, router syslog, sudoers, AD lab rules |
| `ossec-remote-syslog.xml.snippet` | Remote syslog on UDP/514 |
| `active-response/` | HITL host isolation scripts + manager commands |
| `agent-groups/linux/agent.conf` | FIM, logs, audit, Pi-hole file, docker-listener |
| `audit/audit.rules` | Minimal auditd rules for the SIEM Linux host |
| `pihole/` | DNS decoders/rules + bind-mount notes |
| `docker-listener/` | Host SDK pins + DockerListener import-order patch |

## Apply linux group (summary)

```bash
# On the manager container after copying agent.conf into shared/linux/
/var/ossec/bin/agent_groups -a -g linux
# Assign the SIEM-host agent (example id 002) via API or:
/var/ossec/bin/agent_groups -a -i 002 -g linux
```

Then install auditd rules from `audit/audit.rules` and wire Pi-hole logs per `pihole/README.md`.

For container events on the SIEM host, follow [`docker-listener/README.md`](docker-listener/README.md): install `docker==7.1.0` (with pinned urllib3/requests), apply the import-order patch so `wodles/docker` does not shadow the pip SDK, add `wazuh` to the `docker` group, and restart the native agent. Re-apply the patch after every `wazuh-agent` package upgrade.
