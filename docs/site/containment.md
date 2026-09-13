# Containment

Phase E is a **HITL dry-run plan**, not auto-block.

When a HITL case has a source IP, autonomy records a planned command on the case:

```text
sudo -n ufw insert 1 deny from <src> comment agentic-soc-case-N
```

Analyst outcomes **never** run that command. The dashboard **Containment plan** section can **Record UFW plan**. **Execute UFW deny** stays disabled unless `CONTAINMENT_ENABLED=true` on that host, plus an explicit confirm click.

## Safety

Plans are refused for loopback, multicast, unspecified, link-local, and protected lab hosts (default includes `<SIEM_HOST>`). IPv6 is not supported in this slice.

Autonomy **never** calls execute. Default env:

```bash
# CONTAINMENT_ENABLED=false
```

Opt-in execute also needs `sudo -n ufw` to succeed without a password prompt (Pop only). Wrong `ufw allow` from the whole LAN subnet will suppress BLOCK detections — see [Analyst workflow](workflow.md).

Auto-containment (the loop runs UFW with no click) is **deferred**. See [Roadmap](roadmap.md).
