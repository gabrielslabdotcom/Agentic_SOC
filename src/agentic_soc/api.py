"""FastAPI HTTP surface for Agentic SOC tools + analyst dashboard."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

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
    approved: bool
    note: str = ""
    author: str = "human"


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/tools/ui_config")
def ui_config() -> dict[str, Any]:
    """Non-secret UI hints for the analyst dashboard."""
    tools = get_tools()
    settings = tools.settings
    return {
        "app_name": "Agentic SOC Analyst",
        "wazuh_dashboard_url": settings.wazuh_dashboard_url,
        "cases_db_path": str(settings.cases_path),
        "lab_mode": True,
        "containment_enabled": False,
        "note": (
            "Cases DB is local to this API process. Mac and laptop paths are separate "
            "unless CASES_DB_PATH points at the same file or you sync."
        ),
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
    Approve or reject a proposed action (same path as scripts/approve_case.py).

    Lab-safe: updates status + notes only; never executes containment.
    """
    result = get_tools().resolve_proposal(
        case_id,
        approved=body.approved,
        note=body.note,
        author=body.author,
    )
    if result.get("error"):
        raise HTTPException(status_code=404, detail=result)
    return result


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
