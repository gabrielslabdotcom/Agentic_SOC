"""Threat-intel enrichment helpers (VirusTotal, optional AbuseIPDB)."""

from __future__ import annotations

import re
from typing import Any, Optional

import httpx

from agentic_soc.config import Settings, get_settings

_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
_HASH_RE = re.compile(r"^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$")
_URL_RE = re.compile(r"^https?://", re.I)


def detect_ioc_type(ioc: str) -> str:
    value = ioc.strip()
    if _HASH_RE.match(value):
        return "hash"
    if _IPV4_RE.match(value):
        return "ip"
    if _URL_RE.match(value):
        return "url"
    if _DOMAIN_RE.match(value):
        return "domain"
    return "unknown"


class VirusTotalClient:
    """Minimal VirusTotal v3 client for IOC enrichment."""

    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or get_settings()

    @property
    def configured(self) -> bool:
        return bool(self.settings.virustotal_api_key.strip())

    def _headers(self) -> dict[str, str]:
        return {"x-apikey": self.settings.virustotal_api_key.strip()}

    async def verify_auth(self) -> dict[str, Any]:
        """Confirm the API key works without returning the key."""
        if not self.configured:
            return {"ok": False, "error": "VIRUSTOTAL_API_KEY not set in .env"}
        url = f"{self.BASE}/ip_addresses/8.8.8.8"
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(url, headers=self._headers())
        if resp.status_code == 200:
            return {"ok": True, "status_code": 200, "message": "VirusTotal auth OK"}
        if resp.status_code in (401, 403):
            return {
                "ok": False,
                "status_code": resp.status_code,
                "error": "VirusTotal rejected the API key",
            }
        return {
            "ok": False,
            "status_code": resp.status_code,
            "error": f"Unexpected VirusTotal response ({resp.status_code})",
        }

    async def lookup(self, ioc: str, ioc_type: Optional[str] = None) -> dict[str, Any]:
        if not self.configured:
            return {"error": "VIRUSTOTAL_API_KEY not set in .env", "ioc": ioc}

        value = ioc.strip()
        kind = (ioc_type or detect_ioc_type(value)).lower()
        if kind == "unknown":
            return {"error": "unable to detect IOC type", "ioc": value}

        if kind == "hash":
            path = f"/files/{value}"
        elif kind == "ip":
            path = f"/ip_addresses/{value}"
        elif kind == "domain":
            path = f"/domains/{value}"
        elif kind == "url":
            import base64

            url_id = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
            path = f"/urls/{url_id}"
        else:
            return {"error": f"unsupported ioc_type: {kind}", "ioc": value}

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(f"{self.BASE}{path}", headers=self._headers())

        if resp.status_code == 404:
            return {
                "ioc": value,
                "ioc_type": kind,
                "found": False,
                "message": "Not found in VirusTotal",
            }
        if resp.status_code in (401, 403):
            return {"error": "VirusTotal authentication failed", "status_code": resp.status_code, "ioc": value}
        if resp.status_code == 429:
            return {"error": "VirusTotal rate limit exceeded", "status_code": 429, "ioc": value}
        if resp.status_code >= 400:
            return {
                "error": f"VirusTotal HTTP {resp.status_code}",
                "status_code": resp.status_code,
                "ioc": value,
                "ioc_type": kind,
                "detail": (resp.text or "")[:200],
            }

        resp.raise_for_status()
        data = resp.json().get("data", {})
        attrs = data.get("attributes", {}) if isinstance(data, dict) else {}
        stats = attrs.get("last_analysis_stats") or {}
        return {
            "ioc": value,
            "ioc_type": kind,
            "found": True,
            "id": data.get("id"),
            "reputation": attrs.get("reputation"),
            "last_analysis_stats": stats,
            "malicious": int(stats.get("malicious") or 0),
            "suspicious": int(stats.get("suspicious") or 0),
            "harmless": int(stats.get("harmless") or 0),
            "undetected": int(stats.get("undetected") or 0),
            "link": f"https://www.virustotal.com/gui/search/{value}",
        }
