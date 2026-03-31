"""NATO Smart City IoT — FastAPI application entry point."""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from src.api.routes import pipeline, runs, topology

ROOT = Path(__file__).resolve().parents[2]
STATIC_DIR = ROOT / "src" / "static"

app = FastAPI(
    title="NATO Smart City IoT — Pentest Orchestrator",
    version="2.0.0",
    docs_url="/api/docs",
)

# API routers
app.include_router(topology.router, prefix="/api/topology", tags=["topology"])
app.include_router(runs.router,     prefix="/api/runs",     tags=["runs"])
app.include_router(pipeline.router, prefix="/api/pipeline", tags=["pipeline"])

# Serve static files (JS, CSS)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
def index():
    """Serve the SPA."""
    return FileResponse(str(STATIC_DIR / "index.html"))
