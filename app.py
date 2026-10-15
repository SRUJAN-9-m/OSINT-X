"""FastAPI backend + minimal server-rendered dashboard for OSINT-X.

This intentionally ships a lightweight Jinja2 dashboard (a single search
form + results view) rather than a full separate React app, to keep the
project runnable out of the box with `uvicorn app:app`. The API endpoints
below are what a richer frontend (React, etc.) would call; feel free to
build one against them.
"""
from __future__ import annotations

from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from analyzers.correlation import run_investigation
from analyzers.entities import build_graph, graph_to_json
from database.database import (
    delete_investigation,
    init_db,
    load_investigation,
    save_investigation,
)
from database.models import Confidence, Investigation, InvestigationScope
from reports.html_report import generate_html_report
from reports.json_report import generate_json_report
from reports.markdown_report import generate_markdown_report

app = FastAPI(title="OSINT-X API", version="1.0.0")
templates = Jinja2Templates(directory="ui/templates")

# In-memory cache of full Investigation objects for this process (the ORM
# store persists a flattened version to disk/DB; this keeps the rich
# Pydantic object around for report generation without re-querying sources).
_INVESTIGATIONS: dict[str, Investigation] = {}


@app.on_event("startup")
def _startup() -> None:
    init_db()


class NewInvestigationRequest(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    domain: Optional[str] = None
    company: Optional[str] = None
    name: Optional[str] = None
    modules: list[str] = []
    investigator: str = "api-user"


@app.post("/investigation")
async def create_investigation(payload: NewInvestigationRequest):
    scope = InvestigationScope(
        username=payload.username,
        email=payload.email,
        domain=payload.domain,
        company=payload.company,
        name=payload.name,
        modules=payload.modules,
    )
    investigation = await run_investigation(scope, investigator=payload.investigator)
    save_investigation(investigation)
    _INVESTIGATIONS[investigation.id] = investigation
    return {"investigation_id": investigation.id}


def _get_investigation(investigation_id: str) -> Investigation:
    inv = _INVESTIGATIONS.get(investigation_id)
    if inv is None:
        raise HTTPException(404, "Investigation not found (or not in this process's cache -- "
                                  "re-run it, or extend database.py to fully rehydrate from storage).")
    return inv


@app.get("/investigation/{investigation_id}")
async def get_investigation(investigation_id: str):
    inv = _get_investigation(investigation_id)
    return {
        "id": inv.id,
        "investigator": inv.investigator,
        "created_at": inv.created_at,
        "scope": inv.scope,
        "finding_count": len(inv.findings),
    }


@app.get("/investigation/{investigation_id}/findings")
async def get_findings(investigation_id: str):
    inv = _get_investigation(investigation_id)
    return inv.findings


@app.get("/investigation/{investigation_id}/sources")
async def get_sources(investigation_id: str):
    inv = _get_investigation(investigation_id)
    return inv.sources_consulted


@app.get("/investigation/{investigation_id}/graph")
async def get_graph(investigation_id: str):
    inv = _get_investigation(investigation_id)
    return graph_to_json(build_graph(inv))


@app.get("/investigation/{investigation_id}/report")
async def get_report(investigation_id: str, format: str = "json"):
    inv = _get_investigation(investigation_id)
    if format == "json":
        return PlainTextResponse(generate_json_report(inv), media_type="application/json")
    if format == "md":
        return PlainTextResponse(generate_markdown_report(inv), media_type="text/markdown")
    if format == "html":
        return HTMLResponse(generate_html_report(inv))
    raise HTTPException(400, "format must be one of json, md, html")


@app.delete("/investigation/{investigation_id}")
async def remove_investigation(investigation_id: str):
    _INVESTIGATIONS.pop(investigation_id, None)
    ok = delete_investigation(investigation_id)
    if not ok:
        raise HTTPException(404, "Investigation not found")
    return {"deleted": True}


class QuickSearch(BaseModel):
    value: str
    investigator: str = "api-user"


@app.post("/search/username")
async def search_username(payload: QuickSearch):
    scope = InvestigationScope(username=payload.value, modules=["username", "github"])
    inv = await run_investigation(scope, investigator=payload.investigator)
    save_investigation(inv)
    _INVESTIGATIONS[inv.id] = inv
    return {"investigation_id": inv.id, "findings": inv.findings}


@app.post("/search/email")
async def search_email(payload: QuickSearch):
    scope = InvestigationScope(email=payload.value, modules=["email"])
    inv = await run_investigation(scope, investigator=payload.investigator)
    save_investigation(inv)
    _INVESTIGATIONS[inv.id] = inv
    return {"investigation_id": inv.id, "findings": inv.findings}


@app.post("/search/domain")
async def search_domain(payload: QuickSearch):
    scope = InvestigationScope(domain=payload.value, modules=["domain"])
    inv = await run_investigation(scope, investigator=payload.investigator)
    save_investigation(inv)
    _INVESTIGATIONS[inv.id] = inv
    return {"investigation_id": inv.id, "findings": inv.findings}


@app.post("/search/company")
async def search_company(payload: QuickSearch):
    scope = InvestigationScope(company=payload.value, modules=["company"])
    inv = await run_investigation(scope, investigator=payload.investigator)
    save_investigation(inv)
    _INVESTIGATIONS[inv.id] = inv
    return {"investigation_id": inv.id, "findings": inv.findings}


# -- Minimal dashboard ------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"request": request, "investigation": None},
    )


@app.post("/", response_class=HTMLResponse)
async def dashboard_search(request: Request):
    form = await request.form()
    target = (form.get("target") or "").strip()
    kind = form.get("kind") or "domain"
    modules_map = {
        "username": ["username", "github"],
        "email": ["email"],
        "domain": ["domain"],
        "company": ["company"],
    }
    scope = InvestigationScope(**{kind: target}, modules=modules_map.get(kind, []))
    investigation = await run_investigation(scope, investigator="dashboard-user")
    save_investigation(investigation)
    _INVESTIGATIONS[investigation.id] = investigation
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "request": request,
            "investigation": investigation,
            "Confidence": Confidence,
        },
    )
