"""Agent-facing tool surface over Wazuh + local case memory."""

from __future__ import annotations

from typing import Any, Optional

from agentic_soc.cases import CaseStore
from agentic_soc.config import Settings, get_settings
from agentic_soc.enrichment import VirusTotalClient
from agentic_soc.wazuh_client import WazuhClient


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
    ) -> dict[str, Any]:
        return await self.wazuh.list_alerts(
            limit=limit,
            min_level=min_level,
            agent_name=agent_name,
            query_string=query_string,
            exclude_rule_ids=exclude_rule_ids,
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
    ) -> dict[str, Any]:
        return self.cases.open_case(
            title=title,
            alert_id=alert_id,
            agent_name=agent_name,
            summary=summary,
            severity=severity,
            recommended_action=recommended_action,
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

    async def enrich_ioc(
        self,
        ioc: str,
        *,
        ioc_type: Optional[str] = None,
    ) -> dict[str, Any]:
        """Enrich an IOC via VirusTotal (ip / domain / url / hash)."""
        return await self.vt.lookup(ioc, ioc_type=ioc_type)


_tools: Optional[SocTools] = None


def get_tools() -> SocTools:
    global _tools
    if _tools is None:
        _tools = SocTools()
    return _tools
