#!/usr/bin/env python3
"""Lab helper: TCP connect-scan closed ports on the SOC host to generate UFW BLOCK / port-scan alerts."""

from __future__ import annotations

import argparse
import concurrent.futures
import socket
import time


def probe(host: str, port: int, timeout: float) -> tuple[int, int | str]:
    s = socket.socket()
    s.settimeout(timeout)
    try:
        return port, s.connect_ex((host, port))
    except Exception as exc:  # noqa: BLE001
        return port, str(exc)
    finally:
        s.close()


def main() -> int:
    p = argparse.ArgumentParser(description="Generate lab port-scan traffic for Wazuh/UFW detection")
    p.add_argument("--host", default="192.168.50.254")
    p.add_argument("--timeout", type=float, default=0.35)
    p.add_argument("--workers", type=int, default=40)
    p.add_argument(
        "--ports",
        default="1-100,110,135,139,143,445,1433,1521,2049,3306,3389,5432,5900,6379,8080,8443,9000,9999,27017",
        help="Comma list and/or ranges like 1-100",
    )
    p.add_argument(
        "--skip",
        default="22,443,1514,1515,5601,55000,9200",
        help="Ports to skip (allowed lab services)",
    )
    args = p.parse_args()

    ports: list[int] = []
    for part in args.ports.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            ports.extend(range(int(a), int(b) + 1))
        else:
            ports.append(int(part))
    skip = {int(x) for x in args.skip.split(",") if x.strip()}
    ports = sorted({p for p in ports if p not in skip})

    print(f"Scanning {args.host} on {len(ports)} ports (lab traffic for UFW/Wazuh)...")
    started = time.time()
    with concurrent.futures.ThreadPoolExecutor(args.workers) as ex:
        results = list(ex.map(lambda port: probe(args.host, port, args.timeout), ports))
    open_ports = [port for port, rc in results if rc == 0]
    elapsed = time.time() - started
    print(f"Done in {elapsed:.1f}s. connect_ok={open_ports[:20]}")
    print("Wait ~15–30s, then search Wazuh for: Possible port scan / UFW firewall block event")
    print("  python scripts/agent_triage.py --min-level 5 --agent-name pop-os-native")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
