"""Agent-facing tool surface over Wazuh + local case memory."""

from __future__ import annotations

from typing import Any, Optional

from agentic_soc.cases import CaseStore
from agentic_soc.config import Settings, get_settings
from agentic_soc.enrichment import VirusTotalClient
from agentic_soc.triage import extract_iocs, extract_source_ip
from agentic_soc.wazuh_client import WazuhClient

_IOC_TO_ENTITY = {"ip": "ip", "hash": "hash", "domain": "domain"}


def _extract_user(alert: dict[str, Any]) -> Optional[str]:
    raw = alert.get("raw")
    if isinstance(raw, dict):
        data = raw.get("data")
        if isinstance(data, dict):
            for key in ("srcuser", "dstuser", "user"):
                val = data.get(key)
                if val:
                    return str(val).strip()
    return None


class SocTools:
    """Thin facade used by scripts, FastAPI, and future MCP/agent wrappers."""

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or get_settings()
        self.wazuh = WazuhClient(self.settings)
        self.cases = CaseStore(self.settings.cases_path)
        self.vt = VirusTotalClient(self.settings)

    async def list_agents(self, limit: int = 100) -> dict[str, Any]:
        return await self.wazuh.list_agents(limit=limit)

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
        return await self.wazuh.list_alerts(
            limit=limit,
            min_level=min_level,
            agent_name=agent_name,
            query_string=query_string,
            exclude_rule_ids=exclude_rule_ids,
            since=since,
            include_auth_min_level=include_auth_min_level,
        )

    async def get_alert(self, alert_id: str) -> dict[str, Any]:
        return await self.wazuh.get_alert(alert_id)

    def open_case(
        self,
        *,
        title: str,
        alert_id: Optional[str] = None,
        agent_name: Optional[str] = None,
        summary: str = "",
        severity: str = "medium",
        recommended_action: str = "",
        rule_id: Optional[str] = None,
        source_ip: Optional[str] = None,
    ) -> dict[str, Any]:
        return self.cases.open_case(
            title=title,
            alert_id=alert_id,
            agent_name=agent_name,
            summary=summary,
            severity=severity,
            recommended_action=recommended_action,
            rule_id=rule_id,
            source_ip=source_ip,
        )

    def update_case(
        self,
        case_id: int,
        *,
        status: Optional[str] = None,
        disposition: Optional[str] = None,
        summary: Optional[str] = None,
        recommended_action: Optional[str] = None,
        note: Optional[str] = None,
        author: str = "agent",
    ) -> dict[str, Any]:
        return self.cases.update_case(
            case_id,
            status=status,
            disposition=disposition,
            summary=summary,
            recommended_action=recommended_action,
            note=note,
            author=author,
        )

    def get_case(self, case_id: int) -> dict[str, Any]:
        return self.cases.get_case(case_id)

    def list_cases(self, status: Optional[str] = None, limit: int = 50) -> dict[str, Any]:
        return self.cases.list_cases(status=status, limit=limit)

    def propose_action(
        self,
        case_id: int,
        action: str,
        *,
        rationale: str = "",
        auto_execute: bool = False,
    ) -> dict[str, Any]:
        return self.cases.propose_action(
            case_id,
            action,
            rationale=rationale,
            auto_execute=auto_execute,
        )

    def resolve_proposal(
        self,
        case_id: int,
        *,
        approved: bool,
        note: str = "",
        author: str = "human",
    ) -> dict[str, Any]:
        """Approve or reject a proposed action (no auto-containment)."""
        return self.cases.resolve_proposal(
            case_id,
            approved=approved,
            note=note,
            author=author,
        )

    def resolve_proposals(
        self,
        case_ids: list[int],
        *,
        approved: bool,
        note: str = "",
        author: str = "human",
    ) -> dict[str, Any]:
        """Bulk Approve / Reject (no auto-containment)."""
        return self.cases.resolve_proposals(
            case_ids,
            approved=approved,
            note=note,
            author=author,
        )

    def auto_close_noise(
        self,
        case_id: int,
        *,
        note: str = "",
        author: str = "autonomy_loop",
    ) -> dict[str, Any]:
        """Close lab noise without HITL paging (no containment)."""
        return self.cases.auto_close_noise(case_id, note=note, author=author)

    def rejected_similar(
        self,
        *,
        rule_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        days: int = 14,
    ) -> dict[str, Any]:
        return self.cases.rejected_similar(
            rule_id=rule_id,
            source_ip=source_ip,
            days=days,
        )

    def feedback_summary(self, limit: int = 50) -> dict[str, Any]:
        return self.cases.feedback_summary(limit=limit)

    async def enrich_ioc(
        self,
        ioc: str,
        *,
        ioc_type: Optional[str] = None,
    ) -> dict[str, Any]:
        """Enrich an IOC via VirusTotal (ip / domain / url / hash)."""
        return await self.vt.lookup(ioc, ioc_type=ioc_type)

    def upsert_entity(self, entity_type: str, value: str) -> dict[str, Any]:
        return self.cases.upsert_entity(entity_type, value)

    def link_alert_to_entity(
        self,
        entity_id: int,
        alert_id: str,
        *,
        case_id: Optional[int] = None,
    ) -> dict[str, Any]:
        return self.cases.link_alert_to_entity(entity_id, alert_id, case_id=case_id)

    def link_case_to_entity(
        self,
        entity_id: int,
        case_id: int,
        *,
        alert_id: Optional[str] = None,
    ) -> dict[str, Any]:
        return self.cases.link_case_to_entity(entity_id, case_id, alert_id=alert_id)

    def find_related(
        self,
        *,
        case_id: Optional[int] = None,
        alert_id: Optional[str] = None,
        entity_type: Optional[str] = None,
        value: Optional[str] = None,
        entity_id: Optional[int] = None,
        include_hosts: bool = False,
    ) -> dict[str, Any]:
        return self.cases.find_related(
            case_id=case_id,
            alert_id=alert_id,
            entity_type=entity_type,
            value=value,
            entity_id=entity_id,
            include_hosts=include_hosts,
        )

    def correlate_alert(
        self,
        alert: dict[str, Any],
        *,
        case_id: Optional[int] = None,
        alert_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Upsert source IP / agent host / user / IOCs and link them to the case/alert.

        Used by autonomy on case open so a later nmap from the same Kali IP
        shows related cases via find_related.
        """
        aid = (alert_id or alert.get("id") or "")
        aid = str(aid).strip() or None
        linked: list[dict[str, Any]] = []

        def _link(entity: dict[str, Any]) -> None:
            if entity.get("error") or not entity.get("id"):
                linked.append(entity)
                return
            if aid and case_id is not None:
                result = self.link_alert_to_entity(int(entity["id"]), aid, case_id=case_id)
            elif aid:
                result = self.link_alert_to_entity(int(entity["id"]), aid)
            elif case_id is not None:
                result = self.link_case_to_entity(int(entity["id"]), case_id)
            else:
                result = {"error": "alert_id or case_id required"}
            linked.append({"entity": entity, "link": result})

        src = extract_source_ip(alert)
        if src:
            _link(self.upsert_entity("ip", src))

        host = alert.get("agent") or alert.get("agent_name")
        if host:
            _link(self.upsert_entity("host", str(host)))

        user = _extract_user(alert)
        if user:
            _link(self.upsert_entity("user", user))

        for item in extract_iocs(alert):
            kind = _IOC_TO_ENTITY.get(item.get("ioc_type") or "")
            ioc = item.get("ioc")
            if kind and ioc:
                _link(self.upsert_entity(kind, ioc))

        return {"linked": linked, "count": len(linked)}


_tools: Optional[SocTools] = None


def get_tools() -> SocTools:
    global _tools
    if _tools is None:
        _tools = SocTools()
    return _tools
