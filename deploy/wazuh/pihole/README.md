# Pi-hole → Wazuh

Ship Pi-hole query logs to the native agent on the SIEM host via a bind-mounted log directory.

## Host changes (SIEM Linux host)

1. Ensure `/var/log/pihole` exists on the host and add this volume to your Pi-hole compose file (example path `$HOME/pihole/docker-compose.yml`):

```yaml
volumes:
  - ./etc-pihole:/etc/pihole
  - ./etc-dnsmasq.d:/etc/dnsmasq.d
  - /var/log/pihole:/var/log/pihole
```

2. Recreate Pi-hole:

```bash
sudo mkdir -p /var/log/pihole
cd "$HOME/pihole" && docker compose up -d
```

The linux agent group tails `/var/log/pihole/pihole.log`.

3. Merge `decoder.xml` and `rules.xml` into the manager's `local_decoder.xml` / `local_rules.xml`, then restart the manager.

Do **not** open manager UDP/514 for Pi-hole when the agent already reads the file locally.
