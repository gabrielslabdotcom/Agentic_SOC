from __future__ import annotations

from typing import Any, Optional

import httpx

from agentic_soc.config import Settings, get_settings


class WazuhClient:
    """Thin client for Wazuh manager API + indexer (OpenSearch)."""

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or get_settings()
        self._token: Optional[str] = None

    async def authenticate(self) -> str:
        url = f"{self.settings.wazuh_api_url.rstrip('/')}/security/user/authenticate?raw=true"
        async with httpx.AsyncClient(verify=self.settings.wazuh_api_verify_ssl, timeout=30) as client:
            resp = await client.post(
                url,
                auth=(self.settings.wazuh_api_user, self.settings.wazuh_api_password),
            )
            resp.raise_for_status()
            self._token = resp.text.strip().strip('"')
            return self._token

    async def _api_get(self, path: str, params: Optional[dict[str, str]] = None) -> dict[str, Any]:
        if not self._token:
            await self.authenticate()
        url = f"{self.settings.wazuh_api_url.rstrip('/')}{path}"
        async with httpx.AsyncClient(verify=self.settings.wazuh_api_verify_ssl, timeout=30) as client:
            resp = await client.get(
                url,
                headers={"Authorization": f"Bearer {self._token}"},
                params=params or {},
            )
            if resp.status_code == 401:
                await self.authenticate()
                resp = await client.get(
                    url,
                    headers={"Authorization": f"Bearer {self._token}"},
                    params=params or {},
                )
            resp.raise_for_status()
            return resp.json()

    async def list_agents(self, limit: int = 100) -> dict[str, Any]:
        data = await self._api_get("/agents", {"limit": str(limit), "pretty": "true"})
        items = data.get("data", {}).get("affected_items", [])
        agents = [
            {
                "id": a.get("id"),
                "name": a.get("name"),
                "ip": a.get("ip"),
                "status": a.get("status"),
                "os": (a.get("os") or {}).get("name") if isinstance(a.get("os"), dict) else a.get("os"),
                "version": a.get("version"),
            }
            for a in items
        ]
        return {"agents": agents, "total": len(agents)}

    async def agents_summary(self) -> dict[str, Any]:
        data = await self._api_get("/agents/summary/status")
        return data.get("data", data)

    async def list_alerts(
        self,
        *,
        limit: int = 50,
        min_level: int = 0,
        agent_name: Optional[str] = None,
        query_string: Optional[str] = None,
        exclude_rule_ids: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        must: list[dict[str, Any]] = []
        must_not: list[dict[str, Any]] = []
        if min_level > 0:
            must.append({"range": {"rule.level": {"gte": min_level}}})
        if agent_name:
            must.append({"match": {"agent.name": agent_name}})
        if query_string:
            must.append({"query_string": {"query": query_string}})
        if exclude_rule_ids:
            ids = [str(x) for x in exclude_rule_ids if str(x).strip()]
            if ids:
                must_not.append({"terms": {"rule.id": ids}})

        bool_q: dict[str, Any] = {}
        if must:
            bool_q["must"] = must
        if must_not:
            bool_q["must_not"] = must_not
        body: dict[str, Any] = {
            "size": min(limit, 500),
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {"bool": bool_q} if bool_q else {"match_all": {}},
        }

        url = f"{self.settings.wazuh_indexer_url.rstrip('/')}/wazuh-alerts-*/_search"
        async with httpx.AsyncClient(
            verify=self.settings.wazuh_indexer_verify_ssl,
            timeout=30,
        ) as client:
            resp = await client.post(
                url,
                auth=(self.settings.wazuh_indexer_user, self.settings.wazuh_indexer_password),
                json=body,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()

        hits = data.get("hits", {})
        total = hits.get("total", {})
        total_val = total.get("value", 0) if isinstance(total, dict) else total
        docs = []
        for h in hits.get("hits", []):
            src = h.get("_source", {})
            docs.append(
                {
                    "id": h.get("_id"),
                    "timestamp": src.get("timestamp") or src.get("@timestamp"),
                    "agent": (src.get("agent") or {}).get("name"),
                    "rule_id": (src.get("rule") or {}).get("id"),
                    "rule_level": (src.get("rule") or {}).get("level"),
                    "description": (src.get("rule") or {}).get("description"),
                    "mitre": (src.get("rule") or {}).get("mitre"),
                    "full_log": src.get("full_log"),
                    "raw": src,
                }
            )
        return {"total": total_val, "count": len(docs), "alerts": docs}

    async def get_alert(self, alert_id: str) -> dict[str, Any]:
        url = f"{self.settings.wazuh_indexer_url.rstrip('/')}/wazuh-alerts-*/_doc/{alert_id}"
        async with httpx.AsyncClient(
            verify=self.settings.wazuh_indexer_verify_ssl,
            timeout=30,
        ) as client:
            resp = await client.get(
                url,
                auth=(self.settings.wazuh_indexer_user, self.settings.wazuh_indexer_password),
            )
            if resp.status_code == 404:
                # IDs are often only searchable, not directly gettable across aliases
                result = await self.list_alerts(limit=200)
                for alert in result["alerts"]:
                    if alert["id"] == alert_id:
                        return alert
                return {"error": "alert not found", "id": alert_id}
            resp.raise_for_status()
            data = resp.json()
            src = data.get("_source", {})
            return {
                "id": data.get("_id"),
                "timestamp": src.get("timestamp") or src.get("@timestamp"),
                "agent": (src.get("agent") or {}).get("name"),
                "rule_id": (src.get("rule") or {}).get("id"),
                "rule_level": (src.get("rule") or {}).get("level"),
                "description": (src.get("rule") or {}).get("description"),
                "raw": src,
            }
