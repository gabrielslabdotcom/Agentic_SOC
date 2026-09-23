"""stdio MCP server wrapping agentic_soc.tools for Cursor."""

from __future__ import annotations

import json
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

from agentic_soc.policy import INVESTIGATOR
from agentic_soc.tools import get_tools

mcp = FastMCP("agentic_soc")


def _tools():
    """MCP is an investigator. It cannot approve or execute."""
    return get_tools(role=INVESTIGATOR)


def _json(data: Any) -> str:
    return json.dumps(data, default=str, indent=2)


@mcp.tool(name="list_agents", annotations={"readOnlyHint": True, "destructiveHint": False})
async def list_agents(limit: int = 100) -> str:
    """List Wazuh agents and their status from the manager API."""
    return _json(await _tools().list_agents(limit=limit))


@mcp.tool(name="list_alerts", annotations={"readOnlyHint": True, "destructiveHint": False})
async def list_alerts(
    limit: int = 50,
    min_level: int = 0,
    agent_name: Optional[str] = None,
    query_string: Optional[str] = None,
) -> str:
    """List recent Wazuh alerts from the indexer."""
    return _json(
        await _tools().list_alerts(
            limit=limit,
            min_level=min_level,
            agent_name=agent_name,
            query_string=query_string,
        )
    )


@mcp.tool(name="get_alert", annotations={"readOnlyHint": True, "destructiveHint": False})
async def get_alert(alert_id: str) -> str:
    """Fetch one Wazuh alert by document id."""
    return _json(await _tools().get_alert(alert_id))


@mcp.tool(name="open_case", annotations={"readOnlyHint": False, "destructiveHint": False})
async def open_case(
    title: str,
    alert_id: Optional[str] = None,
    agent_name: Optional[str] = None,
    summary: str = "",
    severity: str = "medium",
    recommended_action: str = "",
    rule_id: Optional[str] = None,
    source_ip: Optional[str] = None,
) -> str:
    """Open a local investigation case in SQLite case memory."""
    return _json(
        _tools().open_case(
            title=title,
            alert_id=alert_id,
            agent_name=agent_name,
            summary=summary,
            severity=severity,
            recommended_action=recommended_action,
            rule_id=rule_id,
            source_ip=source_ip,
        )
    )


@mcp.tool(name="update_case", annotations={"readOnlyHint": False, "destructiveHint": False})
async def update_case(
    case_id: int,
    status: Optional[str] = None,
    disposition: Optional[str] = None,
    summary: Optional[str] = None,
    recommended_action: Optional[str] = None,
    note: Optional[str] = None,
    author: str = "agent",
) -> str:
    """Update an existing local case."""
    return _json(
        _tools().update_case(
            case_id,
            status=status,
            disposition=disposition,
            summary=summary,
            recommended_action=recommended_action,
            note=note,
            author=author,
        )
    )


@mcp.tool(name="list_cases", annotations={"readOnlyHint": True, "destructiveHint": False})
async def list_cases(status: Optional[str] = None, limit: int = 50) -> str:
    """List local investigation cases."""
    return _json(_tools().list_cases(status=status, limit=limit))


@mcp.tool(name="propose_action", annotations={"readOnlyHint": False, "destructiveHint": False})
async def propose_action(
    case_id: int,
    action: str,
    rationale: str = "",
    auto_execute: bool = False,
) -> str:
    """Log a response proposal only — never auto-executes containment."""
    return _json(
        _tools().propose_action(
            case_id,
            action,
            rationale=rationale,
            auto_execute=auto_execute,
        )
    )


@mcp.tool(name="enrich_ioc", annotations={"readOnlyHint": True, "destructiveHint": False})
async def enrich_ioc(ioc: str, ioc_type: Optional[str] = None) -> str:
    """Enrich an IOC (ip, domain, url, or hash) via VirusTotal."""
    return _json(await _tools().enrich_ioc(ioc=ioc, ioc_type=ioc_type))


@mcp.tool(name="upsert_entity", annotations={"readOnlyHint": False, "destructiveHint": False})
async def upsert_entity(entity_type: str, value: str) -> str:
    """Insert or refresh a SQLite entity (ip, user, host, hash, domain)."""
    return _json(_tools().upsert_entity(entity_type, value))


@mcp.tool(name="link_alert_to_entity", annotations={"readOnlyHint": False, "destructiveHint": False})
async def link_alert_to_entity(
    entity_id: int,
    alert_id: str,
    case_id: Optional[int] = None,
) -> str:
    """Link an entity to a Wazuh alert (and optionally a case)."""
    return _json(_tools().link_alert_to_entity(entity_id, alert_id, case_id=case_id))


@mcp.tool(name="link_case_to_entity", annotations={"readOnlyHint": False, "destructiveHint": False})
async def link_case_to_entity(
    entity_id: int,
    case_id: int,
    alert_id: Optional[str] = None,
) -> str:
    """Link an entity to a local case (and optionally an alert)."""
    return _json(_tools().link_case_to_entity(entity_id, case_id, alert_id=alert_id))


@mcp.tool(name="find_related", annotations={"readOnlyHint": True, "destructiveHint": False})
async def find_related(
    case_id: Optional[int] = None,
    alert_id: Optional[str] = None,
    entity_type: Optional[str] = None,
    value: Optional[str] = None,
    entity_id: Optional[int] = None,
    include_hosts: bool = False,
) -> str:
    """Find cases/alerts that share SQLite entities (same IP, hash, user, domain)."""
    return _json(
        _tools().find_related(
            case_id=case_id,
            alert_id=alert_id,
            entity_type=entity_type,
            value=value,
            entity_id=entity_id,
            include_hosts=include_hosts,
        )
    )


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
