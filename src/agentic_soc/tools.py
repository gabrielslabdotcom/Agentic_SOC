"""Agent-facing tool surface over Wazuh + local case memory."""

from __future__ import annotations

from typing import Any, Optional

from agentic_soc.cases import CaseStore
from agentic_soc.config import Settings, get_settings
from agentic_soc.containment import (
    execute_block_source_ip,
    plan_block_source_ip,
    plan_note,
)
from agentic_soc.enrichment import VirusTotalClient
from agentic_soc.policy import INVESTIGATOR, allow, denial, normalize_role
from agentic_soc.triage import extract_iocs, extract_source_ip, extract_user
from agentic_soc.wazuh_client import WazuhClient

_IOC_TO_ENTITY = {"ip": "ip", "hash": "hash", "domain": "domain"}


class SocTools:
    """Thin facade used by scripts, FastAPI, and future MCP/agent wrappers."""

    def __init__(self, settings: Optional[Settings] = None, *, role: str = INVESTIGATOR) -> None:
        self.settings = settings or get_settings()
        self.role = normalize_role(role)
        self.wazuh = WazuhClient(self.settings)
        self.cases = CaseStore(self.settings.cases_path)
        self.vt = VirusTotalClient(self.settings)

    def _guard(self, action: str) -> Optional[dict[str, Any]]:
        if allow(self.role, action):
            return None
        return denial(self.role, action)

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
        brief: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        denied = self._guard("open_case")
        if denied:
            return denied
        return self.cases.open_case(
            title=title,
            alert_id=alert_id,
            agent_name=agent_name,
            summary=summary,
            severity=severity,
            recommended_action=recommended_action,
            rule_id=rule_id,
            source_ip=source_ip,
            brief=brief,
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
        denied = self._guard("update_case")
        if denied:
            return denied
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
        denied = self._guard("propose_action")
        if denied:
            return denied
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
        disposition: Optional[str] = None,
        approved: Optional[bool] = None,
        note: str = "",
        author: str = "human",
    ) -> dict[str, Any]:
        """Record an analyst closing outcome (no auto-containment)."""
        denied = self._guard("approve_case")
        if denied:
            return denied
        return self.cases.resolve_proposal(
            case_id,
            disposition=disposition,
            approved=approved,
            note=note,
            author=author,
        )

    def resolve_proposals(
        self,
        case_ids: list[int],
        *,
        disposition: Optional[str] = None,
        approved: Optional[bool] = None,
        note: str = "",
        author: str = "human",
    ) -> dict[str, Any]:
        """Bulk close with an analyst outcome (no auto-containment)."""
        denied = self._guard("approve_case")
        if denied:
            return denied
        return self.cases.resolve_proposals(
            case_ids,
            disposition=disposition,
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
        disposition: Optional[str] = None,
    ) -> dict[str, Any]:
        """Close lab noise without HITL paging (no containment)."""
        denied = self._guard("auto_close_noise")
        if denied:
            return denied
        return self.cases.auto_close_noise(
            case_id,
            note=note,
            author=author,
            disposition=disposition,
        )

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

    def queue_metrics(self) -> dict[str, Any]:
        return self.cases.queue_metrics()

    def list_suppressions(
        self,
        *,
        include_disabled: bool = False,
        limit: int = 100,
    ) -> dict[str, Any]:
        return self.cases.list_suppressions(
            include_disabled=include_disabled,
            limit=limit,
        )

    def add_suppression(
        self,
        *,
        rule_id: str,
        disposition: str = "informational",
        source_ip: Optional[str] = None,
        note: str = "",
        created_by: str = "human",
        expires_at: Optional[str] = None,
    ) -> dict[str, Any]:
        denied = self._guard("add_suppression")
        if denied:
            return denied
        return self.cases.add_suppression(
            rule_id=rule_id,
            disposition=disposition,
            source_ip=source_ip,
            note=note,
            created_by=created_by,
            expires_at=expires_at,
        )

    def disable_suppression(self, suppression_id: int) -> dict[str, Any]:
        denied = self._guard("disable_suppression")
        if denied:
            return denied
        return self.cases.disable_suppression(suppression_id)

    def match_suppression(
        self,
        *,
        rule_id: Optional[str] = None,
        source_ip: Optional[str] = None,
    ) -> dict[str, Any]:
        return self.cases.match_suppression(rule_id=rule_id, source_ip=source_ip)

    def suppression_suggestions(
        self,
        *,
        min_count: int = 2,
        days: int = 30,
        limit: int = 20,
    ) -> dict[str, Any]:
        return self.cases.suppression_suggestions(
            min_count=min_count,
            days=days,
            limit=limit,
        )

    def known_alert_ids(self) -> set[str]:
        return self.cases.known_alert_ids()

    def find_open_incident(
        self,
        *,
        source_ip: Optional[str] = None,
        actor_user: Optional[str] = None,
        hours: int = 6,
    ) -> dict[str, Any]:
        return self.cases.find_open_incident(
            source_ip=source_ip,
            actor_user=actor_user,
            hours=hours,
        )

    def attach_alert(
        self,
        case_id: int,
        *,
        alert_id: Optional[str] = None,
        rule_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        actor_user: Optional[str] = None,
        severity: str = "medium",
        description: str = "",
    ) -> dict[str, Any]:
        denied = self._guard("attach_alert")
        if denied:
            return denied
        return self.cases.attach_alert(
            case_id,
            alert_id=alert_id,
            rule_id=rule_id,
            source_ip=source_ip,
            actor_user=actor_user,
            severity=severity,
            description=description,
        )

    def situation(self, *, limit: int = 50) -> dict[str, Any]:
        return self.cases.situation(limit=limit)

    def plan_containment(
        self,
        *,
        source_ip: Optional[str] = None,
        case_id: Optional[int] = None,
        record: bool = False,
    ) -> dict[str, Any]:
        """Dry-run UFW deny plan. Optional record on the case. Never executes."""
        if record:
            denied = self._guard("record_containment_plan")
            if denied:
                return denied
        ip = source_ip
        if case_id is not None and not ip:
            case = self.cases.get_case(case_id)
            if case.get("error"):
                return case
            ip = case.get("source_ip")
        plan = plan_block_source_ip(ip, case_id=case_id)
        if record and case_id is not None:
            self.cases.update_case(
                case_id,
                note=plan_note(plan),
                author="containment_plan",
            )
            plan["recorded"] = True
        return plan

    def execute_containment(
        self,
        case_id: int,
        *,
        confirm: bool = False,
        source_ip: Optional[str] = None,
        author: str = "human",
    ) -> dict[str, Any]:
        """HITL execute of a planned UFW deny. Off unless CONTAINMENT_ENABLED."""
        denied = self._guard("execute_containment")
        if denied:
            return denied
        case = self.cases.get_case(case_id)
        if case.get("error"):
            return case
        ip = (source_ip or case.get("source_ip") or "").strip() or None
        result = execute_block_source_ip(ip, case_id=case_id, confirm=confirm)
        audit = plan_note(result).replace("[containment_plan]", "[containment_execute]", 1)
        self.cases.update_case(case_id, note=audit, author=author)
        return result

    async def enrich_ioc(
        self,
        ioc: str,
        *,
        ioc_type: Optional[str] = None,
    ) -> dict[str, Any]:
        """Enrich an IOC via VirusTotal (ip / domain / url / hash)."""
        return await self.vt.lookup(ioc, ioc_type=ioc_type)

    def upsert_entity(self, entity_type: str, value: str) -> dict[str, Any]:
        denied = self._guard("upsert_entity")
        if denied:
            return denied
        return self.cases.upsert_entity(entity_type, value)

    def link_alert_to_entity(
        self,
        entity_id: int,
        alert_id: str,
        *,
        case_id: Optional[int] = None,
    ) -> dict[str, Any]:
        denied = self._guard("link_alert_to_entity")
        if denied:
            return denied
        return self.cases.link_alert_to_entity(entity_id, alert_id, case_id=case_id)

    def link_case_to_entity(
        self,
        entity_id: int,
        case_id: int,
        *,
        alert_id: Optional[str] = None,
    ) -> dict[str, Any]:
        denied = self._guard("link_case_to_entity")
        if denied:
            return denied
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
        denied = self._guard("correlate_alert")
        if denied:
            return denied
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

        user = extract_user(alert)
        if user:
            _link(self.upsert_entity("user", user))

        for item in extract_iocs(alert):
            kind = _IOC_TO_ENTITY.get(item.get("ioc_type") or "")
            ioc = item.get("ioc")
            if kind and ioc:
                _link(self.upsert_entity(kind, ioc))

        return {"linked": linked, "count": len(linked)}


_tools: Optional[SocTools] = None


def get_tools(role: str = INVESTIGATOR) -> SocTools:
    """Process-local tools. MCP and scripts stay investigator unless role is set first."""
    global _tools
    if _tools is None:
        _tools = SocTools(role=role)
    return _tools
