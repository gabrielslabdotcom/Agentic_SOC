"""Ask Pop: natural-language search over Wazuh + local cases.

Claude fills typed tool args. This module builds allow-listed OpenSearch/SQL
queries, runs them, and returns grounded rows plus a short answer.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Optional

from agentic_soc.anthropic_llm import (
    DEFAULT_MODEL,
    complete_messages,
    extract_text,
    extract_tool_uses,
)
from agentic_soc.config import Settings, get_settings
from agentic_soc.wazuh_client import ALLOWED_INDEX_PATTERNS, WazuhClient

MAX_HOURS = 30 * 24
MAX_LIMIT = 50
MAX_ROUNDS = 4
MAX_TOOL_RESULT_CHARS = 12000

INVENTORY_CATEGORIES: dict[str, str] = {
    "ports": "wazuh-states-inventory-ports-*",
    "processes": "wazuh-states-inventory-processes-*",
    "packages": "wazuh-states-inventory-packages-*",
    "users": "wazuh-states-inventory-users-*",
    "services": "wazuh-states-inventory-services-*",
    "hotfixes": "wazuh-states-inventory-hotfixes-*",
    "networks": "wazuh-states-inventory-networks-*",
    "interfaces": "wazuh-states-inventory-interfaces-*",
    "system": "wazuh-states-inventory-system-*",
    "hardware": "wazuh-states-inventory-hardware-*",
    "browser_extensions": "wazuh-states-inventory-browser-extensions-*",
    "groups": "wazuh-states-inventory-groups-*",
    "protocols": "wazuh-states-inventory-protocols-*",
}

INVENTORY_FIELD_ALLOWLIST: dict[str, frozenset[str]] = {
    "ports": frozenset(
        {
            "destination.port",
            "destination.ip",
            "source.port",
            "source.ip",
            "process.name",
            "process.pid",
            "network.transport",
            "interface.state",
            "agent.name",
        }
    ),
    "processes": frozenset(
        {
            "process.name",
            "process.pid",
            "process.command_line",
            "process.args",
            "process.parent.pid",
            "agent.name",
        }
    ),
    "packages": frozenset(
        {
            "package.name",
            "package.version",
            "package.vendor",
            "package.type",
            "agent.name",
        }
    ),
    "users": frozenset(
        {
            "user.name",
            "user.id",
            "user.shell",
            "user.home",
            "user.groups",
            "login.status",
            "agent.name",
        }
    ),
    "services": frozenset({"agent.name"}),
    "hotfixes": frozenset({"agent.name"}),
    "networks": frozenset({"agent.name"}),
    "interfaces": frozenset({"agent.name"}),
    "system": frozenset({"agent.name"}),
    "hardware": frozenset({"agent.name"}),
    "browser_extensions": frozenset({"agent.name"}),
    "groups": frozenset({"agent.name"}),
    "protocols": frozenset({"agent.name"}),
}

ALERT_USER_FIELDS = (
    "data.srcuser",
    "data.dstuser",
    "data.win.eventdata.targetUserName",
    "data.win.eventdata.subjectUserName",
)

# Wazuh rule.groups for login / auth hunts (keyword field).
AUTH_RULE_GROUPS = (
    "authentication_success",
    "authentication_failed",
    "authentication_failures",
    "sshd",
    "pam",
)

_AUTH_TEXT_RE = re.compile(
    r"\b(login|logins|logon|logons|logout|logged|signin|sign-in|ssh|sshd|auth|authentication|pam)\b",
    re.I,
)

ALERT_GROUP_BY_FIELDS = {
    "agent": "agent.name",
    "user": "data.srcuser",
    "source_ip": "data.srcip",
    "rule": "rule.id",
}

VULN_GROUP_BY_FIELDS = {
    "agent": "agent.name",
    "severity": "vulnerability.severity",
    "package": "package.name",
    "cve": "vulnerability.id",
}

SEARCH_TOOLS: list[dict[str, Any]] = [
    {
        "name": "search_alerts",
        "description": (
            "Search Wazuh alerts (detections). Use for failed logins, rule hits, "
            "MITRE techniques, source IPs, and users seen in alert traffic."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Free-text keywords"},
                "agent": {"type": "string", "description": "Agent / host name"},
                "user": {"type": "string", "description": "Account name"},
                "source_ip": {"type": "string"},
                "rule_id": {"type": "string"},
                "rule_group": {"type": "string"},
                "min_level": {"type": "integer", "minimum": 0, "maximum": 15},
                "mitre_id": {"type": "string", "description": "e.g. T1110"},
                "hours": {
                    "type": "integer",
                    "description": "Lookback window in hours (max 720)",
                },
                "limit": {"type": "integer", "description": "Max rows (max 50)"},
                "group_by": {
                    "type": "string",
                    "enum": ["agent", "user", "source_ip", "rule"],
                    "description": "Optional top-N aggregation instead of raw rows",
                },
            },
        },
    },
    {
        "name": "search_inventory",
        "description": (
            "Search Wazuh agent inventory state: listening ports, processes, "
            "packages, local users, services, hotfixes, networks."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "enum": sorted(INVENTORY_CATEGORIES.keys()),
                },
                "agent": {"type": "string"},
                "text": {"type": "string"},
                "field_filters": {
                    "type": "object",
                    "description": (
                        "Exact field matches using allow-listed fields for the "
                        "category, e.g. {\"destination.port\": \"3389\"}"
                    ),
                    "additionalProperties": {"type": "string"},
                },
                "limit": {"type": "integer"},
            },
            "required": ["category"],
        },
    },
    {
        "name": "search_vulnerabilities",
        "description": "Search Wazuh vulnerability findings (CVEs) on agents.",
        "input_schema": {
            "type": "object",
            "properties": {
                "agent": {"type": "string"},
                "cve": {"type": "string"},
                "package": {"type": "string"},
                "severity": {
                    "type": "string",
                    "enum": ["Low", "Medium", "High", "Critical"],
                },
                "limit": {"type": "integer"},
                "group_by": {
                    "type": "string",
                    "enum": ["agent", "severity", "package", "cve"],
                },
            },
        },
    },
    {
        "name": "search_cases",
        "description": (
            "Search local Agentic SOC incidents (cases), notes, and linked entities."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "text": {"type": "string"},
                "status": {"type": "string"},
                "severity": {"type": "string"},
                "agent": {"type": "string"},
                "user": {"type": "string"},
                "source_ip": {"type": "string"},
                "limit": {"type": "integer"},
            },
        },
    },
    {
        "name": "list_agents",
        "description": "List Wazuh agents (name, IP, status, OS).",
        "input_schema": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "description": "Optional status filter, e.g. active",
                },
                "limit": {"type": "integer"},
            },
        },
    },
]


def _cap_hours(hours: Any) -> Optional[int]:
    if hours is None or hours == "":
        return None
    try:
        value = int(hours)
    except (TypeError, ValueError):
        return None
    if value <= 0:
        return None
    return min(value, MAX_HOURS)


def _cap_limit(limit: Any, default: int = 25) -> int:
    try:
        value = int(limit) if limit is not None else default
    except (TypeError, ValueError):
        value = default
    return max(1, min(value, MAX_LIMIT))


def _match(field: str, value: str) -> dict[str, Any]:
    return {"match": {field: value}}


def _agent_term(value: str) -> dict[str, Any]:
    """Exact term on keyword ``agent.name``."""
    return {"term": {"agent.name": (value or "").strip()}}


def _term_or_match(field: str, value: str) -> dict[str, Any]:
    cleaned = (value or "").strip()
    if field == "agent.name":
        return _agent_term(cleaned)
    if cleaned.isdigit():
        # Inventory ports and similar long fields need a numeric term.
        return {"term": {field: int(cleaned)}}
    if cleaned.replace(".", "").isdigit() and cleaned.count(".") <= 3:
        return {"term": {field: cleaned}}
    return _match(field, cleaned)


def _normalize_agent_key(name: str) -> str:
    return "".join(ch for ch in (name or "").lower() if ch.isalnum())


def resolve_agent_name(requested: str, known_agents: list[str]) -> str:
    """Map nicknames like ``siemhost`` onto an exact known agent name when unique."""
    cleaned = (requested or "").strip()
    if not cleaned:
        return cleaned
    if not known_agents:
        return cleaned

    for name in known_agents:
        if name.lower() == cleaned.lower():
            return name

    norm = _normalize_agent_key(cleaned)
    if not norm:
        return cleaned

    exact_norm = [n for n in known_agents if _normalize_agent_key(n) == norm]
    if len(exact_norm) == 1:
        return exact_norm[0]

    substr = [
        n
        for n in known_agents
        if norm in _normalize_agent_key(n) or _normalize_agent_key(n) in norm
    ]
    if len(substr) == 1:
        return substr[0]
    return cleaned


def looks_like_auth_text(text: str) -> bool:
    return bool(_AUTH_TEXT_RE.search(text or ""))


def _wildcard_safe_token(token: str) -> str:
    return re.sub(r"[*?\\]", "", (token or "").strip().lower())


def build_alert_text_clause(text: str) -> dict[str, Any]:
    """OR across analyzed full_log, keyword description wildcards, and auth groups."""
    cleaned = (text or "").strip()
    should: list[dict[str, Any]] = []
    if cleaned:
        should.append(
            {
                "simple_query_string": {
                    "query": cleaned,
                    "fields": ["full_log"],
                    "default_operator": "and",
                }
            }
        )
        for raw in re.split(r"\s+", cleaned):
            token = _wildcard_safe_token(raw)
            if len(token) < 2:
                continue
            should.append({"wildcard": {"rule.description": f"*{token}*"}})
    if looks_like_auth_text(cleaned):
        should.append({"terms": {"rule.groups": list(AUTH_RULE_GROUPS)}})
    if not should:
        return {"match_all": {}}
    return {"bool": {"should": should, "minimum_should_match": 1}}


def build_alerts_query(args: dict[str, Any]) -> dict[str, Any]:
    """Build an OpenSearch body for wazuh-alerts-* from validated tool args."""
    must: list[dict[str, Any]] = []
    text = str(args.get("text") or "").strip()
    if text:
        must.append(build_alert_text_clause(text))
    agent = str(args.get("agent") or "").strip()
    if agent:
        must.append(_agent_term(agent))
    user = str(args.get("user") or "").strip()
    if user:
        must.append(
            {
                "bool": {
                    "should": [_match(field, user) for field in ALERT_USER_FIELDS],
                    "minimum_should_match": 1,
                }
            }
        )
    source_ip = str(args.get("source_ip") or "").strip()
    if source_ip:
        must.append(
            {
                "bool": {
                    "should": [
                        _match("data.srcip", source_ip),
                        _match("data.src_ip", source_ip),
                        _match("data.win.eventdata.ipAddress", source_ip),
                    ],
                    "minimum_should_match": 1,
                }
            }
        )
    rule_id = str(args.get("rule_id") or "").strip()
    if rule_id:
        must.append({"term": {"rule.id": rule_id}})
    rule_group = str(args.get("rule_group") or "").strip()
    if rule_group:
        # rule.groups is keyword — exact term, not analyzed match.
        must.append({"term": {"rule.groups": rule_group}})
    min_level = args.get("min_level")
    if min_level is not None and str(min_level).strip() != "":
        try:
            level = max(0, min(int(min_level), 15))
            must.append({"range": {"rule.level": {"gte": level}}})
        except (TypeError, ValueError):
            pass
    mitre_id = str(args.get("mitre_id") or "").strip()
    if mitre_id:
        must.append(
            {
                "bool": {
                    "should": [
                        _match("rule.mitre.id", mitre_id),
                        _match("rule.mitre.technique", mitre_id),
                    ],
                    "minimum_should_match": 1,
                }
            }
        )
    hours = _cap_hours(args.get("hours"))
    if hours:
        must.append({"range": {"@timestamp": {"gte": f"now-{hours}h"}}})

    group_by = str(args.get("group_by") or "").strip().lower()
    if group_by in ALERT_GROUP_BY_FIELDS:
        return {
            "size": 0,
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
            "aggs": {
                "by": {
                    "terms": {
                        "field": ALERT_GROUP_BY_FIELDS[group_by],
                        "size": _cap_limit(args.get("limit"), 20),
                    }
                }
            },
        }
    return {
        "size": _cap_limit(args.get("limit")),
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": must}} if must else {"match_all": {}},
    }


def build_inventory_query(args: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Return ``(index_pattern, body)`` for an inventory category."""
    category = str(args.get("category") or "").strip().lower()
    if category not in INVENTORY_CATEGORIES:
        raise ValueError(f"unknown inventory category: {category}")
    index = INVENTORY_CATEGORIES[category]
    assert index in ALLOWED_INDEX_PATTERNS
    must: list[dict[str, Any]] = []
    agent = str(args.get("agent") or "").strip()
    if agent:
        must.append(_agent_term(agent))
    text = str(args.get("text") or "").strip()
    if text:
        must.append({"simple_query_string": {"query": text, "default_operator": "and"}})
    allow = INVENTORY_FIELD_ALLOWLIST.get(category, frozenset())
    raw_filters = args.get("field_filters")
    if isinstance(raw_filters, dict):
        for key, value in raw_filters.items():
            field = str(key or "").strip()
            val = "" if value is None else str(value).strip()
            if not field or not val:
                continue
            if field not in allow:
                raise ValueError(f"field not allowed for {category}: {field}")
            must.append(_term_or_match(field, val))
    body = {
        "size": _cap_limit(args.get("limit")),
        "query": {"bool": {"must": must}} if must else {"match_all": {}},
    }
    return index, body


def build_vulnerabilities_query(args: dict[str, Any]) -> dict[str, Any]:
    must: list[dict[str, Any]] = []
    agent = str(args.get("agent") or "").strip()
    if agent:
        must.append(_agent_term(agent))
    cve = str(args.get("cve") or "").strip()
    if cve:
        must.append({"term": {"vulnerability.id": cve}})
    package = str(args.get("package") or "").strip()
    if package:
        must.append(_match("package.name", package))
    severity = str(args.get("severity") or "").strip()
    if severity:
        must.append({"term": {"vulnerability.severity": severity}})
    group_by = str(args.get("group_by") or "").strip().lower()
    if group_by in VULN_GROUP_BY_FIELDS:
        return {
            "size": 0,
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
            "aggs": {
                "by": {
                    "terms": {
                        "field": VULN_GROUP_BY_FIELDS[group_by],
                        "size": _cap_limit(args.get("limit"), 20),
                    }
                }
            },
        }
    return {
        "size": _cap_limit(args.get("limit")),
        "query": {"bool": {"must": must}} if must else {"match_all": {}},
    }


def slim_alert(source: dict[str, Any], *, doc_id: Optional[str] = None) -> dict[str, Any]:
    rule = source.get("rule") if isinstance(source.get("rule"), dict) else {}
    agent = source.get("agent") if isinstance(source.get("agent"), dict) else {}
    data = source.get("data") if isinstance(source.get("data"), dict) else {}
    win = data.get("win") if isinstance(data.get("win"), dict) else {}
    eventdata = win.get("eventdata") if isinstance(win.get("eventdata"), dict) else {}
    full_log = source.get("full_log")
    if isinstance(full_log, str) and len(full_log) > 400:
        full_log = full_log[:399] + "…"
    return {
        "id": doc_id,
        "timestamp": source.get("timestamp") or source.get("@timestamp"),
        "agent": agent.get("name"),
        "rule_id": rule.get("id"),
        "rule_level": rule.get("level"),
        "description": rule.get("description"),
        "srcip": data.get("srcip") or eventdata.get("ipAddress"),
        "user": data.get("srcuser")
        or data.get("dstuser")
        or eventdata.get("targetUserName"),
        "full_log": full_log,
    }


def slim_inventory(source: dict[str, Any], *, category: str, doc_id: Optional[str] = None) -> dict[str, Any]:
    agent = source.get("agent") if isinstance(source.get("agent"), dict) else {}
    out: dict[str, Any] = {
        "id": doc_id,
        "category": category,
        "agent": agent.get("name"),
        "agent_ip": (agent.get("host") or {}).get("ip")
        if isinstance(agent.get("host"), dict)
        else None,
    }
    for key in (
        "destination",
        "source",
        "process",
        "package",
        "user",
        "network",
        "interface",
        "login",
    ):
        if key in source:
            out[key] = source[key]
    return out


def slim_vulnerability(source: dict[str, Any], *, doc_id: Optional[str] = None) -> dict[str, Any]:
    agent = source.get("agent") if isinstance(source.get("agent"), dict) else {}
    vuln = source.get("vulnerability") if isinstance(source.get("vulnerability"), dict) else {}
    package = source.get("package") if isinstance(source.get("package"), dict) else {}
    return {
        "id": doc_id,
        "agent": agent.get("name"),
        "cve": vuln.get("id"),
        "severity": vuln.get("severity"),
        "score": (vuln.get("score") or {}).get("base")
        if isinstance(vuln.get("score"), dict)
        else None,
        "package": package.get("name"),
        "package_version": package.get("version"),
        "description": vuln.get("description"),
    }


def slim_case(case: dict[str, Any]) -> dict[str, Any]:
    notes = case.get("notes") if isinstance(case.get("notes"), list) else []
    note_preview = ""
    if notes and isinstance(notes[0], dict):
        note_preview = str(notes[0].get("note") or "")[:240]
    return {
        "id": case.get("id"),
        "title": case.get("title"),
        "status": case.get("status"),
        "severity": case.get("severity"),
        "agent_name": case.get("agent_name"),
        "source_ip": case.get("source_ip"),
        "actor_user": case.get("actor_user"),
        "rule_id": case.get("rule_id"),
        "summary": (case.get("summary") or "")[:300],
        "updated_at": case.get("updated_at"),
        "note_preview": note_preview,
    }


def _agg_buckets(aggs: dict[str, Any]) -> list[dict[str, Any]]:
    by = aggs.get("by") if isinstance(aggs, dict) else None
    if not isinstance(by, dict):
        return []
    buckets = by.get("buckets")
    if not isinstance(buckets, list):
        return []
    return [
        {"key": b.get("key"), "count": b.get("doc_count")}
        for b in buckets
        if isinstance(b, dict)
    ]


def _clip_json(payload: Any, limit: int = MAX_TOOL_RESULT_CHARS) -> str:
    text = json.dumps(payload, default=str)
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


class SearchEngine:
    """Execute Ask Pop tool calls and the Claude tool loop."""

    def __init__(
        self,
        settings: Optional[Settings] = None,
        *,
        wazuh: Optional[WazuhClient] = None,
        cases: Any = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.wazuh = wazuh or WazuhClient(self.settings)
        if cases is None:
            from agentic_soc.cases import CaseStore

            self.cases = CaseStore(self.settings.cases_path)
        else:
            self.cases = cases
        self._known_agents: list[str] = []

    def _system_prompt(self, agent_names: list[str]) -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        agents = ", ".join(agent_names[:40]) if agent_names else "(unknown)"
        return (
            "You are Ask Pop, a read-only SOC search assistant for Agentic SOC.\n"
            f"Current time: {now}.\n"
            f"Known agents: {agents}.\n"
            "Use the provided tools to answer the analyst question.\n"
            "When filtering by agent, copy the name EXACTLY from Known agents "
            "(e.g. siem-host, not siemhost).\n"
            "For login/auth/ssh questions prefer rule_group values like sshd or "
            "authentication_success, or text such as session / Accepted — not only "
            "the word login.\n"
            "Prefer precise filters (agent, user, IP, port, CVE, hours) over broad text.\n"
            "Never invent hosts, users, CVEs, or counts — only use tool results.\n"
            "If the first tool call returns 0 hits, retry once with the exact agent "
            "name from Known agents and broader auth filters before concluding there "
            "are no events.\n"
            "Do not propose containment, isolation, or case changes.\n"
            "Answer briefly with the key findings, then mention notable evidence."
        )

    def _resolve_args(self, args: dict[str, Any]) -> dict[str, Any]:
        """Return a copy of tool args with agent nicknames resolved."""
        out = dict(args)
        agent = str(out.get("agent") or "").strip()
        if not agent:
            return out
        resolved = resolve_agent_name(agent, self._known_agents)
        out["agent"] = resolved
        if resolved != agent:
            out["agent_requested"] = agent
        return out

    async def _load_known_agents(self) -> list[str]:
        """Prefer manager inventory; fall back to distinct agent.name from alerts."""
        try:
            agents_payload = await self.wazuh.list_agents(limit=100)
            names = [
                str(a.get("name"))
                for a in (agents_payload.get("agents") or [])
                if a.get("name")
            ]
            if names:
                return names
        except Exception:  # noqa: BLE001
            pass
        try:
            raw = await self.wazuh.search_index(
                "wazuh-alerts-*",
                {
                    "size": 0,
                    "aggs": {
                        "agents": {"terms": {"field": "agent.name", "size": 50}}
                    },
                },
            )
            buckets = ((raw.get("aggregations") or {}).get("agents") or {}).get(
                "buckets"
            ) or []
            return [str(b.get("key")) for b in buckets if isinstance(b, dict) and b.get("key")]
        except Exception:  # noqa: BLE001
            return []

    async def execute_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        args = args if isinstance(args, dict) else {}
        if name == "search_alerts":
            return await self._search_alerts(args)
        if name == "search_inventory":
            return await self._search_inventory(args)
        if name == "search_vulnerabilities":
            return await self._search_vulnerabilities(args)
        if name == "search_cases":
            return self._search_cases(args)
        if name == "list_agents":
            return await self._list_agents(args)
        return {"ok": False, "error": f"unknown_tool:{name}"}

    async def _search_alerts(self, args: dict[str, Any]) -> dict[str, Any]:
        resolved = self._resolve_args(args)
        body = build_alerts_query(resolved)
        raw = await self.wazuh.search_index("wazuh-alerts-*", body)
        if not raw.get("ok"):
            return {**raw, "resolved_args": resolved}
        if "aggs" in body or body.get("size") == 0:
            buckets = _agg_buckets(raw.get("aggregations") or {})
            return {
                "ok": True,
                "source": "alerts",
                "total": raw.get("total", 0),
                "count": len(buckets),
                "group_by": resolved.get("group_by"),
                "buckets": buckets,
                "rows": [],
                "resolved_args": resolved,
            }
        rows = [
            slim_alert(h.get("source") or {}, doc_id=h.get("id"))
            for h in raw.get("hits") or []
        ]
        return {
            "ok": True,
            "source": "alerts",
            "total": raw.get("total", 0),
            "count": len(rows),
            "rows": rows,
            "resolved_args": resolved,
        }

    async def _search_inventory(self, args: dict[str, Any]) -> dict[str, Any]:
        resolved = self._resolve_args(args)
        try:
            index, body = build_inventory_query(resolved)
        except ValueError as exc:
            return {
                "ok": False,
                "error": str(exc),
                "source": "inventory",
                "resolved_args": resolved,
            }
        category = str(resolved.get("category") or "").strip().lower()
        raw = await self.wazuh.search_index(index, body)
        if not raw.get("ok"):
            return {**raw, "resolved_args": resolved}
        rows = [
            slim_inventory(h.get("source") or {}, category=category, doc_id=h.get("id"))
            for h in raw.get("hits") or []
        ]
        return {
            "ok": True,
            "source": "inventory",
            "category": category,
            "total": raw.get("total", 0),
            "count": len(rows),
            "rows": rows,
            "resolved_args": resolved,
        }

    async def _search_vulnerabilities(self, args: dict[str, Any]) -> dict[str, Any]:
        resolved = self._resolve_args(args)
        body = build_vulnerabilities_query(resolved)
        raw = await self.wazuh.search_index("wazuh-states-vulnerabilities-*", body)
        if not raw.get("ok"):
            return {**raw, "resolved_args": resolved}
        if body.get("size") == 0:
            buckets = _agg_buckets(raw.get("aggregations") or {})
            return {
                "ok": True,
                "source": "vulnerabilities",
                "total": raw.get("total", 0),
                "count": len(buckets),
                "group_by": resolved.get("group_by"),
                "buckets": buckets,
                "rows": [],
                "resolved_args": resolved,
            }
        rows = [
            slim_vulnerability(h.get("source") or {}, doc_id=h.get("id"))
            for h in raw.get("hits") or []
        ]
        return {
            "ok": True,
            "source": "vulnerabilities",
            "total": raw.get("total", 0),
            "count": len(rows),
            "rows": rows,
            "resolved_args": resolved,
        }

    def _search_cases(self, args: dict[str, Any]) -> dict[str, Any]:
        result = self.cases.search_cases(
            text=str(args.get("text") or "").strip() or None,
            status=str(args.get("status") or "").strip() or None,
            severity=str(args.get("severity") or "").strip() or None,
            agent=str(args.get("agent") or "").strip() or None,
            user=str(args.get("user") or "").strip() or None,
            source_ip=str(args.get("source_ip") or "").strip() or None,
            limit=_cap_limit(args.get("limit")),
        )
        rows = [slim_case(c) for c in result.get("cases") or []]
        return {
            "ok": True,
            "source": "cases",
            "total": result.get("total", len(rows)),
            "count": len(rows),
            "rows": rows,
        }

    async def _list_agents(self, args: dict[str, Any]) -> dict[str, Any]:
        limit = _cap_limit(args.get("limit"), 100)
        # list_agents already caps at manager API; fetch then filter
        data = await self.wazuh.list_agents(limit=min(limit, 500))
        agents = list(data.get("agents") or [])
        status = str(args.get("status") or "").strip().lower()
        if status:
            agents = [a for a in agents if str(a.get("status") or "").lower() == status]
        agents = agents[:limit]
        return {
            "ok": True,
            "source": "agents",
            "total": len(agents),
            "count": len(agents),
            "rows": agents,
        }

    async def keyword_fallback(self, question: str) -> dict[str, Any]:
        text = (question or "").strip()
        steps: list[dict[str, Any]] = []
        results: dict[str, Any] = {
            "alerts": [],
            "inventory": [],
            "vulnerabilities": [],
            "cases": [],
            "agents": [],
            "buckets": [],
        }
        if not text:
            return {
                "ok": True,
                "mode": "keyword",
                "model": None,
                "answer": "Enter a question or keywords to search.",
                "steps": [],
                "results": results,
            }
        # No default hours cap — lab alert indices can be older than a week.
        alert_args = {"text": text, "limit": 25}
        alert_result = await self._search_alerts(alert_args)

        steps.append(
            {
                "tool": "search_alerts",
                "args": alert_args,
                "hit_count": alert_result.get("count", 0),
                "total": alert_result.get("total", 0),
            }
        )
        results["alerts"] = alert_result.get("rows") or []

        case_args = {"text": text, "limit": 25}
        case_result = self._search_cases(case_args)
        steps.append(
            {
                "tool": "search_cases",
                "args": case_args,
                "hit_count": case_result.get("count", 0),
                "total": case_result.get("total", 0),
            }
        )
        results["cases"] = case_result.get("rows") or []

        n_alerts = len(results["alerts"])
        n_cases = len(results["cases"])
        answer = (
            f"Keyword search (no Anthropic key configured). "
            f"Found {n_alerts} alert(s) and {n_cases} case(s) matching "
            f"{text!r}. Enable the Anthropic connector for natural-language answers."
        )
        return {
            "ok": True,
            "mode": "keyword",
            "model": None,
            "answer": answer,
            "steps": steps,
            "results": results,
        }

    async def run_search(self, question: str) -> dict[str, Any]:
        text = (question or "").strip()
        if not text:
            return await self.keyword_fallback("")

        key = (self.settings.anthropic_api_key or "").strip()
        if not key:
            return await self.keyword_fallback(text)

        base = (self.settings.anthropic_base_url or "").strip() or "https://api.anthropic.com"
        model = (self.settings.anthropic_model or "").strip() or DEFAULT_MODEL

        agent_names = await self._load_known_agents()
        self._known_agents = agent_names

        messages: list[dict[str, Any]] = [{"role": "user", "content": text}]
        steps: list[dict[str, Any]] = []
        results: dict[str, Any] = {
            "alerts": [],
            "inventory": [],
            "vulnerabilities": [],
            "cases": [],
            "agents": [],
            "buckets": [],
        }
        answer = ""
        stop_reason = ""

        for _round in range(MAX_ROUNDS):
            try:
                payload = await complete_messages(
                    base_url=base,
                    api_key=key,
                    model=model,
                    messages=messages,
                    system=self._system_prompt(agent_names),
                    tools=SEARCH_TOOLS,
                    max_tokens=1200,
                )
            except Exception as exc:  # noqa: BLE001
                fallback = await self.keyword_fallback(text)
                fallback["answer"] = (
                    f"Anthropic call failed ({exc}). Fell back to keyword search.\n\n"
                    + str(fallback.get("answer") or "")
                )
                fallback["error"] = str(exc)
                return fallback

            stop_reason = str(payload.get("stop_reason") or "")
            tool_uses = extract_tool_uses(payload)
            content = payload.get("content")
            if not isinstance(content, list):
                content = []

            if not tool_uses:
                answer = extract_text(payload) or "No answer returned."
                break

            # Append assistant turn with tool_use blocks, then tool results.
            messages.append({"role": "assistant", "content": content})
            tool_results: list[dict[str, Any]] = []
            for use in tool_uses:
                name = use["name"]
                args = use["input"]
                executed = await self.execute_tool(name, args)
                hit_count = int(executed.get("count") or 0)
                step_args = executed.get("resolved_args") or args
                steps.append(
                    {
                        "tool": name,
                        "args": step_args,
                        "hit_count": hit_count,
                        "total": executed.get("total", hit_count),
                        "error": executed.get("error"),
                    }
                )
                self._merge_results(results, executed)
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": use["id"],
                        "content": _clip_json(
                            {
                                "ok": executed.get("ok", True),
                                "source": executed.get("source"),
                                "total": executed.get("total"),
                                "count": executed.get("count"),
                                "group_by": executed.get("group_by"),
                                "buckets": executed.get("buckets"),
                                "rows": executed.get("rows"),
                                "error": executed.get("error"),
                            }
                        ),
                    }
                )
            messages.append({"role": "user", "content": tool_results})
        else:
            # Round cap hit without a final text answer — ask once more without tools.
            try:
                payload = await complete_messages(
                    base_url=base,
                    api_key=key,
                    model=model,
                    messages=messages
                    + [
                        {
                            "role": "user",
                            "content": (
                                "Stop calling tools. Summarize the findings from the "
                                "tool results already gathered."
                            ),
                        }
                    ],
                    system=self._system_prompt(agent_names),
                    max_tokens=800,
                )
                answer = extract_text(payload) or "Reached the tool-call limit."
                stop_reason = str(payload.get("stop_reason") or "max_rounds")
            except Exception:  # noqa: BLE001
                answer = "Reached the tool-call limit before a final answer."
                stop_reason = "max_rounds"

        if not answer:
            answer = "No answer returned."

        return {
            "ok": True,
            "mode": "llm",
            "model": model,
            "answer": answer,
            "steps": steps,
            "results": results,
            "stop_reason": stop_reason,
        }

    def _merge_results(self, results: dict[str, Any], executed: dict[str, Any]) -> None:
        source = str(executed.get("source") or "")
        rows = executed.get("rows") if isinstance(executed.get("rows"), list) else []
        buckets = executed.get("buckets") if isinstance(executed.get("buckets"), list) else []
        if buckets:
            results["buckets"].extend(buckets)
        if source == "alerts":
            results["alerts"].extend(rows)
        elif source == "inventory":
            results["inventory"].extend(rows)
        elif source == "vulnerabilities":
            results["vulnerabilities"].extend(rows)
        elif source == "cases":
            results["cases"].extend(rows)
        elif source == "agents":
            results["agents"].extend(rows)


async def run_search(
    question: str,
    *,
    settings: Optional[Settings] = None,
) -> dict[str, Any]:
    return await SearchEngine(settings=settings).run_search(question)
