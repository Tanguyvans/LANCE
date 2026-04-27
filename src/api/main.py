"""NATO Smart City IoT — FastAPI application entry point."""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from src.api.routes import models, pipeline, runs, scenarios, topology

ROOT = Path(__file__).resolve().parents[2]
STATIC_DIR    = ROOT / "src" / "static"
STATIC_V2_DIR = ROOT / "src" / "static_v2"

app = FastAPI(
    title="NATO Smart City IoT — Pentest Orchestrator",
    version="2.0.0",
    docs_url="/api/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API routers
app.include_router(topology.router,  prefix="/api/topology",  tags=["topology"])
app.include_router(runs.router,      prefix="/api/runs",      tags=["runs"])
app.include_router(pipeline.router,  prefix="/api/pipeline",  tags=["pipeline"])
app.include_router(scenarios.router, prefix="/api/scenarios", tags=["scenarios"])
app.include_router(models.router,    prefix="/api/models",    tags=["models"])

# Serve static files (JS, CSS) — no-cache pour forcer le rechargement
app.mount("/static",    StaticFiles(directory=str(STATIC_DIR)),    name="static")
app.mount("/static_v2", StaticFiles(directory=str(STATIC_V2_DIR)), name="static_v2")


_CACHEABLE_API_PATHS = {"/api/models", "/api/scenarios"}

@app.middleware("http")
async def cache_control(request: Request, call_next) -> Response:
    response = await call_next(request)
    path = request.url.path
    if path.startswith("/static/") or path.startswith("/static_v2/") or path in ("/", "/v2"):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    elif path in _CACHEABLE_API_PATHS:
        response.headers["Cache-Control"] = "public, max-age=3600"
    return response


@app.get("/", include_in_schema=False)
def index():
    """Serve the classic SPA."""
    return FileResponse(str(STATIC_DIR / "index.html"))


@app.get("/v2", include_in_schema=False)
def index_v2():
    """Serve the new monitor dashboard."""
    return FileResponse(str(STATIC_V2_DIR / "index.html"))
