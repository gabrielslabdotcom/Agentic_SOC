from __future__ import annotations

from typing import Any, Optional

import httpx

from agentic_soc.config import Settings, get_settings
from agentic_soc.triage import AUTH_FAILURE_GROUPS, AUTH_FAILURE_RULE_IDS


def build_alerts_search_body(
    *,
    limit: int = 50,
    min_level: int = 0,
    agent_name: Optional[str] = None,
    query_string: Optional[str] = None,
    exclude_rule_ids: Optional[list[str]] = None,
    since: Optional[str] = None,
    include_auth_min_level: Optional[int] = None,
) -> dict[str, Any]:
    """OpenSearch body for wazuh-alerts-*.

    With ``since``, sort oldest-first so a truncated burst continues on the next
    poll instead of skipping older alerts in the window.

    ``include_auth_min_level`` ORs in sshd/PAM auth failures at that floor
    without lowering the global ``min_level`` (Phase C: keep live min-level 8).
    """
    must: list[dict[str, Any]] = []
    must_not: list[dict[str, Any]] = []
    names = [n.strip() for n in (agent_name or "").split(",") if n.strip()]
    if len(names) == 1:
        must.append({"match": {"agent.name": names[0]}})
    elif len(names) > 1:
        must.append({"terms": {"agent.name": names}})
    if query_string:
        must.append({"query_string": {"query": query_string}})
    since_ts = (since or "").strip()
    if since_ts:
        must.append({"range": {"@timestamp": {"gt": since_ts}}})
    if exclude_rule_ids:
        ids = [str(x) for x in exclude_rule_ids if str(x).strip()]
        if ids:
            must_not.append({"terms": {"rule.id": ids}})

    level_clause: dict[str, Any] | None = None
    if min_level > 0:
        level_clause = {"range": {"rule.level": {"gte": min_level}}}

    auth_clause: dict[str, Any] | None = None
    if include_auth_min_level is not None:
        auth_clause = {
            "bool": {
                "must": [
                    {"range": {"rule.level": {"gte": int(include_auth_min_level)}}},
                    {
                        "bool": {
                            "should": [
                                {"terms": {"rule.groups": sorted(AUTH_FAILURE_GROUPS)}},
                                {"terms": {"rule.id": sorted(AUTH_FAILURE_RULE_IDS)}},
                            ],
                            "minimum_should_match": 1,
                        }
                    },
                ]
            }
        }

    if level_clause and auth_clause:
        must.append(
            {"bool": {"should": [level_clause, auth_clause], "minimum_should_match": 1}}
        )
    elif level_clause:
        must.append(level_clause)
    elif auth_clause:
        must.append(auth_clause)

    bool_q: dict[str, Any] = {}
    if must:
        bool_q["must"] = must
    if must_not:
        bool_q["must_not"] = must_not
    order = "asc" if since_ts else "desc"
    return {
        "size": min(limit, 500),
        "sort": [{"@timestamp": {"order": order}}],
        "query": {"bool": bool_q} if bool_q else {"match_all": {}},
    }


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

    async def _api_put(
        self,
        path: str,
        body: dict[str, Any],
        params: Optional[dict[str, str]] = None,
    ) -> dict[str, Any]:
        if not self._token:
            await self.authenticate()
        url = f"{self.settings.wazuh_api_url.rstrip('/')}{path}"
        async with httpx.AsyncClient(verify=self.settings.wazuh_api_verify_ssl, timeout=30) as client:
            resp = await client.put(
                url,
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Content-Type": "application/json",
                },
                params=params or {},
                json=body,
            )
            if resp.status_code == 401:
                await self.authenticate()
                resp = await client.put(
                    url,
                    headers={
                        "Authorization": f"Bearer {self._token}",
                        "Content-Type": "application/json",
                    },
                    params=params or {},
                    json=body,
                )
            resp.raise_for_status()
            return resp.json()

    def _agent_record(self, raw: dict[str, Any]) -> dict[str, Any]:
        os_info = raw.get("os")
        os_name = os_info.get("name") if isinstance(os_info, dict) else os_info
        platform = os_info.get("platform") if isinstance(os_info, dict) else None
        return {
            "id": raw.get("id"),
            "name": raw.get("name"),
            "ip": raw.get("ip"),
            "status": raw.get("status"),
            "os": os_name,
            "platform": platform,
            "version": raw.get("version"),
        }

    async def list_agents(self, limit: int = 100) -> dict[str, Any]:
        data = await self._api_get("/agents", {"limit": str(limit), "pretty": "true"})
        items = data.get("data", {}).get("affected_items", [])
        agents = [self._agent_record(a) for a in items]
        return {"agents": agents, "total": len(agents)}

    async def agents_summary(self) -> dict[str, Any]:
        data = await self._api_get("/agents/summary/status")
        return data.get("data", data)

    async def resolve_agent_by_name(self, name: str) -> dict[str, Any]:
        """Exact-match one Wazuh agent by name. Ambiguous names are an error."""
        cleaned = (name or "").strip()
        if not cleaned:
            return {"ok": False, "error": "no_agent_name", "agent_name": None, "matches": []}
        items: list[dict[str, Any]] = []
        try:
            data = await self._api_get("/agents", {"q": f"name={cleaned}", "limit": "50"})
            items = list(data.get("data", {}).get("affected_items") or [])
        except httpx.HTTPStatusError:
            items = []
        exact = [a for a in items if str(a.get("name") or "") == cleaned]
        if not exact:
            data = await self._api_get("/agents", {"limit": "500"})
            items = list(data.get("data", {}).get("affected_items") or [])
            exact = [a for a in items if str(a.get("name") or "") == cleaned]
        matches = [self._agent_record(a) for a in exact]
        if not matches:
            return {
                "ok": False,
                "error": "agent_not_found",
                "agent_name": cleaned,
                "matches": [],
            }
        if len(matches) > 1:
            return {
                "ok": False,
                "error": "agent_name_ambiguous",
                "agent_name": cleaned,
                "matches": matches,
            }
        return {"ok": True, "agent": matches[0], "agent_name": cleaned, "matches": matches}

    async def list_active_response_commands(self) -> dict[str, Any]:
        """Registered active-response commands (manager API)."""
        return await self._api_get("/active-response")

    async def active_response(
        self,
        agent_ids: list[str],
        command: str,
        arguments: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """PUT /active-response for one or more agent ids. Does not retry on failure."""
        ids = ",".join(str(i).strip() for i in agent_ids if str(i).strip())
        body: dict[str, Any] = {"command": command}
        if arguments:
            body["arguments"] = list(arguments)
        return await self._api_put("/active-response", body, {"agents_list": ids})

    async def list_alerts(
        self,
        *,
        limit: int = 50,
        min_level: int = 0,
        agent_name: Optional[str] = None,
        query_string: Optional[str] = None,
        exclude_rule_ids: Optional[list[str]] = None,
        since: Optional[str] = None,
        include_auth_min_level: Optional[int] = None,
    ) -> dict[str, Any]:
        body = build_alerts_search_body(
            limit=limit,
            min_level=min_level,
            agent_name=agent_name,
            query_string=query_string,
            exclude_rule_ids=exclude_rule_ids,
            since=since,
            include_auth_min_level=include_auth_min_level,
        )

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
