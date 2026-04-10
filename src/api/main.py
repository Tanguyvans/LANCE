"""NATO Smart City IoT — FastAPI application entry point."""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from src.api.routes import pipeline, runs, scenarios, topology

ROOT = Path(__file__).resolve().parents[2]
STATIC_DIR = ROOT / "src" / "static"

app = FastAPI(
    title="NATO Smart City IoT — Pentest Orchestrator",
    version="2.0.0",
    docs_url="/api/docs",
)

# API routers
app.include_router(topology.router,  prefix="/api/topology",  tags=["topology"])
app.include_router(runs.router,      prefix="/api/runs",      tags=["runs"])
app.include_router(pipeline.router,  prefix="/api/pipeline",  tags=["pipeline"])
app.include_router(scenarios.router, prefix="/api/scenarios", tags=["scenarios"])

# Serve static files (JS, CSS) — no-cache pour forcer le rechargement
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.middleware("http")
async def no_cache_static(request: Request, call_next) -> Response:
    response = await call_next(request)
    if request.url.path.startswith("/static/") or request.url.path == "/":
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


@app.get("/", include_in_schema=False)
def index():
    """Serve the SPA."""
    return FileResponse(str(STATIC_DIR / "index.html"))
