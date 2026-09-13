# Prerequisites

Operator detail: [SETUP_GUIDE.md §1](../SETUP_GUIDE.md).

## Both machines

- Same LAN (the Mac must reach the Pop SIEM host, typically `<SIEM_HOST>`)
- Docker Engine on Pop!_OS (Wazuh single-node images need several GB)
- Python 3.11+ on the Mac (and on Pop for autonomy)

## Mac

- SSH client (built into macOS)
- An SSH key authorized on the laptop (this lab uses `~/.ssh/id_ed25519`)
- Cursor, if you want MCP tools in chat

## Pop!_OS laptop

- User with Docker access (prefer Docker without sudo for day-to-day)
- Ports you will publish for the lab: SSH `22`, Wazuh agent `1514/1515`, manager API `55000`, indexer `9200`, dashboard `443` (and related)

## What you are not installing yet

- Security Onion, Neo4j, a SOAR, or Cursor Hydra
- Binding the unauthenticated analyst API on `0.0.0.0`

Next: [Installation — SSH](installation-ssh.md).
