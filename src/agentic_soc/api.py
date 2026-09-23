"""FastAPI HTTP surface for Agentic SOC tools + analyst dashboard."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, model_validator

from agentic_soc.analyst_outcomes import coerce_analyst_disposition
from agentic_soc.config import hostname
from agentic_soc.tools import get_tools

_STATIC_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(
    title="Agentic SOC Tools",
    description="Lab tool API for Wazuh triage and local case memory.",
    version="0.1.0",
)


class OpenCaseBody(BaseModel):
    title: str
    alert_id: Optional[str] = None
    agent_name: Optional[str] = None
    summary: str = ""
    severity: str = "medium"
    recommended_action: str = ""
    rule_id: Optional[str] = None
    source_ip: Optional[str] = None
    brief: Optional[dict[str, Any]] = None


class UpdateCaseBody(BaseModel):
    status: Optional[str] = None
    disposition: Optional[str] = None
    summary: Optional[str] = None
    recommended_action: Optional[str] = None
    note: Optional[str] = None
    author: str = "agent"


class ProposeActionBody(BaseModel):
    action: str
    rationale: str = ""
    auto_execute: bool = Field(
        default=False,
        description="Ignored in lab mode — proposals are never auto-executed.",
    )


class ApproveCaseBody(BaseModel):
    approved: Optional[bool] = Field(
        default=None,
        description="Deprecated alias: true→confirmed_compromise, false→false_positive.",
    )
    disposition: Optional[str] = Field(
        default=None,
        description="Analyst outcome: false_positive, benign, informational, duplicate, confirmed_compromise.",
    )
    note: str = ""
    author: str = "human"

    @model_validator(mode="after")
    def _require_outcome(self) -> ApproveCaseBody:
        try:
            self.disposition = coerce_analyst_disposition(
                disposition=self.disposition, approved=self.approved
            )
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
        return self


class BulkApproveBody(BaseModel):
    case_ids: list[int] = Field(..., min_length=1, max_length=100)
    approved: Optional[bool] = None
    disposition: Optional[str] = None
    note: str = ""
    author: str = "human"

    @model_validator(mode="after")
    def _require_outcome(self) -> BulkApproveBody:
        try:
            self.disposition = coerce_analyst_disposition(
                disposition=self.disposition, approved=self.approved
            )
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
        return self


class UpsertEntityBody(BaseModel):
    entity_type: str
    value: str


class LinkAlertEntityBody(BaseModel):
    entity_id: int
    alert_id: str
    case_id: Optional[int] = None


class LinkCaseEntityBody(BaseModel):
    entity_id: int
    case_id: int
    alert_id: Optional[str] = None


class ExecuteContainmentBody(BaseModel):
    case_id: int
    confirm: bool = False
    source_ip: Optional[str] = None
    author: str = "dashboard"


class AddSuppressionBody(BaseModel):
    rule_id: str
    disposition: str = "informational"
    source_ip: Optional[str] = None
    note: str = ""
    created_by: str = "dashboard"
    expires_at: Optional[str] = None


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/tools/ui_config")
def ui_config() -> dict[str, Any]:
    """Non-secret UI hints for the analyst dashboard."""
    tools = get_tools()
    settings = tools.settings
    instance = settings.resolve_instance()
    live = instance == "pop-live"
    min_level = os.environ.get("AUTONOMY_MIN_LEVEL", "8")
    if live:
        note = (
            "LIVE Pop cases (Discord / autonomy DB). Analyst outcomes "
            "(false positive, benign, informational, duplicate, confirmed compromise) "
            "record status + note only. Containment is never executed. Live min-level "
            "stays 8; sshd/PAM auth failures at level 5 are OR'd in (AUTONOMY_INCLUDE_AUTH). "
            "False positive / benign / informational / duplicate on the same "
            "rule_id+source IP skips repeats. Confirmed compromise does not skip. "
            "Informational/FP cases may auto-close without Discord "
            "(AUTONOMY_AUTO_CLOSE_NOISE). UFW deny is a dry-run plan unless "
            "CONTAINMENT_ENABLED=true (still HITL, never auto)."
        )
        banner = "LIVE Pop cases — Discord / autonomy DB. Not the Mac local copy."
    else:
        note = (
            "Mac local copy of cases.sqlite — this is NOT the Discord / autonomy DB on Pop. "
            "Open live cases at http://192.168.50.254:8080/ (UFW allowlisted). "
            "Optional fallback: ./scripts/tunnel_pop_dashboard.sh → http://127.0.0.1:8081/"
        )
        banner = "Mac local copy — not Discord / Pop autonomy cases. Live UI: http://192.168.50.254:8080/"
    return {
        "app_name": "Agentic SOC Analyst",
        "instance": instance,
        "hostname": hostname(),
        "wazuh_dashboard_url": settings.wazuh_dashboard_url,
        "cases_db_path": str(settings.cases_path),
        "lab_mode": True,
        "containment_enabled": os.environ.get("CONTAINMENT_ENABLED", "false").lower()
        in ("1", "true", "yes"),
        "autonomy_min_level": min_level,
        "include_auth": os.environ.get("AUTONOMY_INCLUDE_AUTH", "true"),
        "auto_close_noise": os.environ.get("AUTONOMY_AUTO_CLOSE_NOISE", "true"),
        "banner": banner,
        "note": note,
    }


@app.get("/tools/list_agents")
async def list_agents(limit: int = Query(100, ge=1, le=500)) -> dict[str, Any]:
    return await get_tools().list_agents(limit=limit)


@app.get("/tools/list_alerts")
async def list_alerts(
    limit: int = Query(50, ge=1, le=500),
    min_level: int = Query(0, ge=0, le=15),
    agent_name: Optional[str] = None,
    query_string: Optional[str] = None,
) -> dict[str, Any]:
    return await get_tools().list_alerts(
        limit=limit,
        min_level=min_level,
        agent_name=agent_name,
        query_string=query_string,
    )


@app.get("/tools/get_alert/{alert_id}")
async def get_alert(alert_id: str) -> dict[str, Any]:
    result = await get_tools().get_alert(alert_id)
    if result.get("error"):
        raise HTTPException(status_code=404, detail=result)
    return result


@app.post("/tools/open_case")
def open_case(body: OpenCaseBody) -> dict[str, Any]:
    return get_tools().open_case(**body.model_dump())


@app.patch("/tools/update_case/{case_id}")
def update_case(case_id: int, body: UpdateCaseBody) -> dict[str, Any]:
    result = get_tools().update_case(case_id, **body.model_dump(exclude_unset=True))
    if result.get("error"):
        raise HTTPException(status_code=404, detail=result)
    return result


@app.get("/tools/get_case/{case_id}")
def get_case(case_id: int) -> dict[str, Any]:
    result = get_tools().get_case(case_id)
    if result.get("error"):
        raise HTTPException(status_code=404, detail=result)
    return result


@app.get("/tools/list_cases")
def list_cases(
    status: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
) -> dict[str, Any]:
    # UI "pending" = cases awaiting human decision (DB status is "open")
    if status == "pending":
        status = "open"
    return get_tools().list_cases(status=status, limit=limit)


@app.post("/tools/approve_case/{case_id}")
def approve_case(case_id: int, body: ApproveCaseBody) -> dict[str, Any]:
    """
    Record an analyst closing outcome (same path as scripts/approve_case.py).

    Lab-safe: updates status + notes only; never executes containment.
    """
    result = get_tools().resolve_proposal(
        case_id,
        disposition=body.disposition,
        note=body.note,
        author=body.author,
    )
    if result.get("error"):
        err = str(result.get("error") or "")
        if "unknown analyst" in err or "provide disposition" in err:
            raise HTTPException(status_code=400, detail=result)
        raise HTTPException(status_code=404, detail=result)
    return result


@app.post("/tools/approve_cases")
def approve_cases(body: BulkApproveBody) -> dict[str, Any]:
    """
    Bulk close with an analyst outcome (same record-only path as a single close).

    Skips cases that are not open. Never executes containment.
    """
    return get_tools().resolve_proposals(
        body.case_ids,
        disposition=body.disposition,
        note=body.note,
        author=body.author,
    )


@app.get("/tools/feedback_summary")
def feedback_summary(limit: int = Query(50, ge=1, le=200)) -> dict[str, Any]:
    """Human closing-outcome history used to skip repeat lab noise."""
    return get_tools().feedback_summary(limit=limit)


@app.get("/tools/queue_metrics")
def queue_metrics() -> dict[str, Any]:
    """Opened / auto-closed / human-outcome counts for the analyst UI strip."""
    return get_tools().queue_metrics()


@app.get("/tools/situation")
def situation(limit: int = Query(50, ge=1, le=200)) -> dict[str, Any]:
    """Open incidents grouped by source IP or user. Actor-less cases stay ungrouped."""
    return get_tools().situation(limit=limit)


@app.get("/tools/list_suppressions")
def list_suppressions(
    include_disabled: bool = Query(False),
    limit: int = Query(100, ge=1, le=500),
) -> dict[str, Any]:
    return get_tools().list_suppressions(
        include_disabled=include_disabled,
        limit=limit,
    )


@app.post("/tools/add_suppression")
def add_suppression(body: AddSuppressionBody) -> dict[str, Any]:
    """Analyst-managed rule suppression (auto-close before Discord/Cursor)."""
    result = get_tools().add_suppression(
        rule_id=body.rule_id,
        disposition=body.disposition,
        source_ip=body.source_ip,
        note=body.note,
        created_by=body.created_by,
        expires_at=body.expires_at,
    )
    if result.get("error"):
        raise HTTPException(status_code=400, detail=result)
    return result


@app.post("/tools/disable_suppression/{suppression_id}")
def disable_suppression(suppression_id: int) -> dict[str, Any]:
    result = get_tools().disable_suppression(suppression_id)
    if result.get("error"):
        raise HTTPException(status_code=404, detail=result)
    return result


@app.get("/tools/match_suppression")
def match_suppression(
    rule_id: str = Query(..., min_length=1),
    source_ip: Optional[str] = Query(None),
) -> dict[str, Any]:
    return get_tools().match_suppression(rule_id=rule_id, source_ip=source_ip)


@app.get("/tools/suppression_suggestions")
def suppression_suggestions(
    min_count: int = Query(2, ge=2, le=50),
    days: int = Query(30, ge=1, le=365),
    limit: int = Query(20, ge=1, le=100),
) -> dict[str, Any]:
    """Repeated skippable feedback — for review; never auto-promoted."""
    return get_tools().suppression_suggestions(
        min_count=min_count,
        days=days,
        limit=limit,
    )


@app.post("/tools/propose_action/{case_id}")
def propose_action(case_id: int, body: ProposeActionBody) -> dict[str, Any]:
    result = get_tools().propose_action(
        case_id,
        body.action,
        rationale=body.rationale,
        auto_execute=body.auto_execute,
    )
    if result.get("error"):
        raise HTTPException(status_code=404, detail=result)
    return result


@app.get("/tools/containment_plan")
def containment_plan(
    case_id: Optional[int] = Query(None),
    source_ip: Optional[str] = Query(None),
    record: bool = Query(False),
) -> dict[str, Any]:
    """Dry-run UFW deny plan. Never executes."""
    if case_id is None and not (source_ip or "").strip():
        raise HTTPException(status_code=400, detail={"error": "case_id or source_ip required"})
    return get_tools().plan_containment(
        source_ip=source_ip,
        case_id=case_id,
        record=record,
    )


@app.post("/tools/execute_containment")
def execute_containment(body: ExecuteContainmentBody) -> dict[str, Any]:
    """HITL UFW deny. No-op unless CONTAINMENT_ENABLED=true and confirm=true."""
    result = get_tools().execute_containment(
        body.case_id,
        confirm=body.confirm,
        source_ip=body.source_ip,
        author=body.author,
    )
    if result.get("error") and result.get("id"):
        raise HTTPException(status_code=404, detail=result)
    return result


@app.post("/tools/upsert_entity")
def upsert_entity(body: UpsertEntityBody) -> dict[str, Any]:
    result = get_tools().upsert_entity(body.entity_type, body.value)
    if result.get("error"):
        raise HTTPException(status_code=400, detail=result)
    return result


@app.post("/tools/link_alert_to_entity")
def link_alert_to_entity(body: LinkAlertEntityBody) -> dict[str, Any]:
    result = get_tools().link_alert_to_entity(
        body.entity_id,
        body.alert_id,
        case_id=body.case_id,
    )
    if result.get("error"):
        raise HTTPException(status_code=404, detail=result)
    return result


@app.post("/tools/link_case_to_entity")
def link_case_to_entity(body: LinkCaseEntityBody) -> dict[str, Any]:
    result = get_tools().link_case_to_entity(
        body.entity_id,
        body.case_id,
        alert_id=body.alert_id,
    )
    if result.get("error"):
        raise HTTPException(status_code=404, detail=result)
    return result


@app.get("/tools/find_related")
def find_related(
    case_id: Optional[int] = None,
    alert_id: Optional[str] = None,
    entity_type: Optional[str] = None,
    value: Optional[str] = None,
    entity_id: Optional[int] = None,
    include_hosts: bool = False,
) -> dict[str, Any]:
    result = get_tools().find_related(
        case_id=case_id,
        alert_id=alert_id,
        entity_type=entity_type,
        value=value,
        entity_id=entity_id,
        include_hosts=include_hosts,
    )
    if result.get("error"):
        raise HTTPException(status_code=400, detail=result)
    return result


@app.get("/tools/enrich_ioc")
async def enrich_ioc(
    ioc: str = Query(..., min_length=1),
    ioc_type: Optional[str] = Query(
        None,
        description="Optional override: ip | domain | url | hash",
    ),
) -> dict[str, Any]:
    result = await get_tools().enrich_ioc(ioc, ioc_type=ioc_type)
    if result.get("error") and "not set" in str(result.get("error")):
        raise HTTPException(status_code=400, detail=result)
    if result.get("error") and result.get("status_code") in (401, 403):
        raise HTTPException(status_code=502, detail=result)
    return result


@app.get("/")
async def root() -> RedirectResponse:
    return RedirectResponse(url="/dashboard/")


@app.get("/dashboard")
async def dashboard_redirect() -> RedirectResponse:
    return RedirectResponse(url="/dashboard/")


@app.get("/dashboard/")
async def dashboard_index() -> FileResponse:
    index = _STATIC_DIR / "index.html"
    if not index.is_file():
        raise HTTPException(status_code=404, detail="Dashboard static files not found")
    return FileResponse(index)


if _STATIC_DIR.is_dir():
    app.mount(
        "/dashboard/static",
        StaticFiles(directory=str(_STATIC_DIR)),
        name="dashboard_static",
    )
