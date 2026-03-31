"""Pipeline route — start pipeline and stream events via SSE."""
from __future__ import annotations

import asyncio
import json
import sys
import threading
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

router = APIRouter()

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Global pipeline state (single concurrent run)
_state: dict[str, Any] = {
    "running": False,
    "phase": 0,
    "cost": 0.0,
    "run_dir": None,
    "queue": None,
    "loop": None,
}


class StartRequest(BaseModel):
    model: str = "google/gemini-2.0-flash-001"
    provider: str = "openrouter"
    scenario_id: int | None = None
    phases: list[int] | None = None
    auto_teardown: bool = True


def _pipeline_thread(req: StartRequest):
    """Run the pipeline in a background thread, pushing events to the async queue."""
    try:
        from dotenv import load_dotenv
        load_dotenv(ROOT / ".env")

        from src.agent.provider import LLMProvider
        from src.agent.pipeline import Pipeline

        provider = LLMProvider(provider=req.provider, model=req.model)
        pipeline = Pipeline(
            provider=provider,
            phases=req.phases or None,
            scenario_id=req.scenario_id,
            auto_teardown=req.auto_teardown,
        )

        def callback(event: dict):
            loop = _state["loop"]
            q = _state["queue"]
            if loop and q:
                loop.call_soon_threadsafe(q.put_nowait, event)
            # Update shared state
            t = event.get("type")
            if t == "phase_start":
                _state["phase"] = event.get("phase", _state["phase"])
            elif t == "phase_done":
                _state["cost"] += event.get("cost_usd", 0.0)
            elif t == "pipeline_done":
                _state["run_dir"] = event.get("run_dir")
                _state["cost"] = event.get("total_cost_usd", _state["cost"])

        pipeline.run(stream_callback=callback)

    except Exception as exc:
        q = _state["queue"]
        loop = _state["loop"]
        if loop and q:
            loop.call_soon_threadsafe(q.put_nowait, {"type": "error", "message": str(exc)})
    finally:
        _state["running"] = False
        # Signal stream end
        q = _state["queue"]
        loop = _state["loop"]
        if loop and q:
            loop.call_soon_threadsafe(q.put_nowait, {"type": "__done__"})


@router.post("/start")
async def start_pipeline(req: StartRequest):
    """Start the pipeline. Returns 409 if already running."""
    if _state["running"]:
        raise HTTPException(status_code=409, detail="Pipeline already running")

    _state["running"] = True
    _state["phase"] = 0
    _state["cost"] = 0.0
    _state["run_dir"] = None
    _state["queue"] = asyncio.Queue()
    _state["loop"] = asyncio.get_event_loop()

    thread = threading.Thread(target=_pipeline_thread, args=(req,), daemon=True)
    thread.start()
    return {"status": "started"}


@router.get("/status")
def get_status():
    """Return current pipeline state."""
    return {
        "running": _state["running"],
        "phase": _state["phase"],
        "cost": round(_state["cost"], 4),
        "run_dir": _state["run_dir"],
    }


@router.get("/stream")
async def stream_events():
    """SSE endpoint — streams pipeline events until done."""
    q = _state.get("queue")
    if q is None:
        raise HTTPException(status_code=400, detail="No active pipeline run")

    async def generator():
        while True:
            try:
                event = await asyncio.wait_for(q.get(), timeout=30.0)
            except asyncio.TimeoutError:
                # Keep-alive ping
                yield {"event": "ping", "data": "{}"}
                continue

            if event.get("type") == "__done__":
                break
            yield {"data": json.dumps(event)}
            if event.get("type") in ("pipeline_done", "error"):
                break

    return EventSourceResponse(generator())
