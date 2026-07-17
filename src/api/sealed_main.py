"""Dedicated evaluator-gateway FastAPI application.

Deploy this app on an evaluator-owned host, never in the public orchestrator
process or on a machine where harness workers have root access.  It exposes no
pipeline, run, topology, static-file or artifact route.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from src.api.routes import sealed


SEALED_STATIC_DIR = Path(__file__).resolve().parents[1] / "sealed_static"
_HOST_RE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?|\[[0-9A-Fa-f:]+\])$")


def _allowed_hosts() -> list[str]:
    """Fail closed to loopback unless evaluator hostnames are explicit."""

    raw = os.environ.get("SEALED_ALLOWED_HOSTS", "")
    if not raw:
        return ["localhost", "127.0.0.1", "[::1]"]
    hosts: list[str] = []
    for value in raw.split(","):
        host = value.strip()
        if host and host != "*" and _HOST_RE.fullmatch(host) and host not in hosts:
            hosts.append(host)
    return hosts or ["localhost", "127.0.0.1", "[::1]"]


app = FastAPI(
    title="IoTChainBench Sealed Evaluation Gateway",
    version="2.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=_allowed_hosts())
app.include_router(sealed.router, prefix="/api/sealed", tags=["sealed"])
app.mount(
    "/assets",
    StaticFiles(directory=str(SEALED_STATIC_DIR)),
    name="sealed-assets",
)


@app.middleware("http")
async def sealed_security_headers(request: Request, call_next) -> Response:
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    )
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'self'; object-src 'none'; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
    )
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    """Serve the evaluator-owned UI; never serve the public harness SPA."""

    return FileResponse(SEALED_STATIC_DIR / "index.html")


@app.get("/healthz", include_in_schema=False)
def healthz() -> dict[str, str]:
    # Deliberately does not disclose controller/provider configuration.
    return {"status": "ok"}
