"""stdio MCP server wrapping agentic_soc.tools for Cursor."""

from __future__ import annotations

import json
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

from agentic_soc.tools import get_tools

mcp = FastMCP("agentic_soc")


def _json(data: Any) -> str:
    return json.dumps(data, default=str, indent=2)


@mcp.tool(name="list_agents", annotations={"readOnlyHint": True, "destructiveHint": False})
async def list_agents(limit: int = 100) -> str:
    """List Wazuh agents and their status from the manager API."""
    return _json(await get_tools().list_agents(limit=limit))


@mcp.tool(name="list_alerts", annotations={"readOnlyHint": True, "destructiveHint": False})
async def list_alerts(
    limit: int = 50,
    min_level: int = 0,
    agent_name: Optional[str] = None,
    query_string: Optional[str] = None,
) -> str:
    """List recent Wazuh alerts from the indexer."""
    return _json(
        await get_tools().list_alerts(
            limit=limit,
            min_level=min_level,
            agent_name=agent_name,
            query_string=query_string,
        )
    )


@mcp.tool(name="get_alert", annotations={"readOnlyHint": True, "destructiveHint": False})
async def get_alert(alert_id: str) -> str:
    """Fetch one Wazuh alert by document id."""
    return _json(await get_tools().get_alert(alert_id))


@mcp.tool(name="open_case", annotations={"readOnlyHint": False, "destructiveHint": False})
async def open_case(
    title: str,
    alert_id: Optional[str] = None,
    agent_name: Optional[str] = None,
    summary: str = "",
    severity: str = "medium",
    recommended_action: str = "",
) -> str:
    """Open a local investigation case in SQLite case memory."""
    return _json(
        get_tools().open_case(
            title=title,
            alert_id=alert_id,
            agent_name=agent_name,
            summary=summary,
            severity=severity,
            recommended_action=recommended_action,
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
        get_tools().update_case(
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
    return _json(get_tools().list_cases(status=status, limit=limit))


@mcp.tool(name="propose_action", annotations={"readOnlyHint": False, "destructiveHint": False})
async def propose_action(
    case_id: int,
    action: str,
    rationale: str = "",
    auto_execute: bool = False,
) -> str:
    """Log a response proposal only — never auto-executes containment."""
    return _json(
        get_tools().propose_action(
            case_id,
            action,
            rationale=rationale,
            auto_execute=auto_execute,
        )
    )


@mcp.tool(name="enrich_ioc", annotations={"readOnlyHint": True, "destructiveHint": False})
async def enrich_ioc(ioc: str, ioc_type: Optional[str] = None) -> str:
    """Enrich an IOC (ip, domain, url, or hash) via VirusTotal."""
    return _json(await get_tools().enrich_ioc(ioc=ioc, ioc_type=ioc_type))


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
