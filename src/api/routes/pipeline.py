"""Pipeline route — start pipeline and stream events via SSE."""
from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from src.benchmark.scenario_exports import default_export_store, resolve_ground_truth_path

router = APIRouter()

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Global pipeline state (single concurrent run)
_state: dict[str, Any] = {
    "running": False,
    "stopping": False,
    "teardown_running": False,
    "phase": 0,
    "phase_name": "",
    "cost": 0.0,
    "run_dir": None,
    "queue": None,
    "loop": None,
    "stop_event": None,   # threading.Event | None
    # Run metadata
    "scenario_id": None,
    "model": None,
    "execution_profile": None,
    "execution_profile_policy": None,
    "started_at": None,
    # Progress tracking
    "phases_done": [],        # [{"phase": 1, "name": "graph_analysis", "cost": 0.01, "duration_s": 42}]
    "current_devices": [],    # ["s1-mqtt", "s1-web"] — devices being scanned in current phase
    "devices_done": [],       # ["s1-mqtt"] — devices completed in current phase
    "deploy_status": None,    # "deploying" | "deployed" | "failed" | None
    "recent_events": [],      # last 200 events, replayed on page reload
}
_state_lock = threading.Lock()

_MAX_RECENT_EVENTS = 200


class StartRequest(BaseModel):
    model: str = "google/gemini-2.0-flash-001"
    provider: str = "openrouter"
    scenario_id: str | None = None
    phases: list[int] | None = None
    auto_teardown: bool = True
    max_cost_usd: float | None = None
    phase_models: dict[int, str] | None = None
    # Discovery mode (Docker end-user): scan a live network instead of a pre-defined topology
    target_network: str | None = None  # CIDR e.g. "192.168.1.0/24"
    # Deploy-only mode: run Ansible deploy+inject but skip all pentest phases
    deploy_only: bool = False
    # Blind mode: deploy scenario VMs but hide topology from agent (forces discovery)
    blind: bool = False
    # Custom mode fields
    architecture: str | None = None
    posture: str | None = None       # "vulnerable" | "hardened"
    selected_packs: list[str] | None = None
    excluded_vulns: list[str] | None = None  # vuln IDs to exclude from GT
    execution_profile: Literal["auto", "compact", "full"] = "auto"


def _pipeline_thread(req: StartRequest):
    """Run the pipeline in a background thread, pushing events to the async queue."""
    try:
        from dotenv import load_dotenv
        load_dotenv(ROOT / ".env")

        from src.agent.provider import LLMProvider
        from src.agent.pipeline import Pipeline

        # If phase_models is provided, we'll instantiate providers dynamically in Pipeline
        # but we need a default one for the init and cost tracking setup
        default_model = req.model
        if req.phase_models and req.phases and req.phases[0] in req.phase_models:
            default_model = req.phase_models[req.phases[0]]

        provider = LLMProvider(provider=req.provider, model=default_model)

        # Build custom config if in custom mode
        custom_config = None
        if req.architecture:
            custom_config = {
                "architecture": req.architecture,
                "posture": req.posture or "vulnerable",
                "selected_packs": req.selected_packs or [],
                "excluded_vulns": req.excluded_vulns or [],
            }

        pipeline = Pipeline(
            provider=provider,
            phases=req.phases or None,
            scenario_id=req.scenario_id,
            auto_teardown=req.auto_teardown,
            max_cost_usd=req.max_cost_usd,
            phase_models=req.phase_models,
            custom_config=custom_config,
            manage_scenario=not default_export_store().exists(req.scenario_id or ""),
            target_network=req.target_network,
            blind=req.blind,
            execution_profile=req.execution_profile,
        )

        def callback(event: dict):
            loop = _state["loop"]
            q = _state["queue"]
            if loop and q:
                loop.call_soon_threadsafe(q.put_nowait, event)
            # Buffer event for page-reload replay (skip internal/noise events)
            _skip = {"__done__", "ping", "text_chunk"}
            if event.get("type") not in _skip:
                _state["recent_events"].append(event)
                if len(_state["recent_events"]) > _MAX_RECENT_EVENTS:
                    _state["recent_events"] = _state["recent_events"][-_MAX_RECENT_EVENTS:]
            # Update shared state from events
            t = event.get("type")
            if t == "phase_start":
                _state["phase"] = event.get("phase", _state["phase"])
                _state["phase_name"] = event.get("agent", "")
                _state["current_devices"] = []
                _state["devices_done"] = []
            elif t == "phase_done":
                cost = event.get("cost_usd", 0.0)
                _state["cost"] += cost
                _state["phases_done"].append({
                    "phase": event.get("phase"),
                    "name": event.get("agent", ""),
                    "cost": cost,
                    "duration_s": event.get("duration_s", 0),
                })
            elif t == "device_start":
                dev = event.get("device_id", "")
                if dev and dev not in _state["current_devices"]:
                    _state["current_devices"].append(dev)
            elif t == "device_done":
                dev = event.get("device_id", "")
                if dev and dev not in _state["devices_done"]:
                    _state["devices_done"].append(dev)
            elif t == "deploy_start":
                _state["deploy_status"] = "deploying"
            elif t == "deploy_done":
                _state["deploy_status"] = "deployed" if event.get("success") else "failed"
            elif t in {"inject_done", "verify_done"} and not event.get("success"):
                _state["deploy_status"] = "failed"
            elif t == "pipeline_done":
                _state["run_dir"] = event.get("run_dir")
                _state["cost"] = event.get("total_cost_usd", _state["cost"])

        if req.deploy_only:
            pipeline.run_deploy_only(stream_callback=callback)
        else:
            pipeline.run(stream_callback=callback, stop_event=_state["stop_event"])

    except Exception as exc:
        q = _state["queue"]
        loop = _state["loop"]
        if loop and q:
            loop.call_soon_threadsafe(q.put_nowait, {"type": "error", "message": str(exc)})
    finally:
        with _state_lock:
            _state["running"] = False
            _state["stopping"] = False
        # Signal stream end
        q = _state["queue"]
        loop = _state["loop"]
        if loop and q:
            loop.call_soon_threadsafe(q.put_nowait, {"type": "__done__"})


@router.post("/start")
async def start_pipeline(req: StartRequest):
    """Start the pipeline. Returns 409 if already running."""
    if req.scenario_id is not None:
        from src.agent.batch import SealedScenarioError, _parse_single_scenario_id
        try:
            req.scenario_id = _parse_single_scenario_id(req.scenario_id)
        except SealedScenarioError as exc:
            raise HTTPException(
                status_code=503,
                detail=(
                    "S24-S29 require the external sealed controller and isolated worker. "
                    "They cannot run inside the dashboard process."
                ),
            ) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if req.deploy_only and default_export_store().exists(req.scenario_id):
            raise HTTPException(
                status_code=400,
                detail="Scenario Lab exports support dashboard analysis, not Proxmox provisioning",
            )

    from datetime import datetime
    from src.agent.execution_profiles import resolve_execution_profile_for_model
    profile_resolution = resolve_execution_profile_for_model(
        req.execution_profile, req.model
    )
    with _state_lock:
        if _state["running"]:
            raise HTTPException(status_code=409, detail="Pipeline already running or stopping")
        if _state["teardown_running"]:
            raise HTTPException(status_code=409, detail="Scenario teardown is still running")
        _state["running"] = True
        _state["stopping"] = False
    _state["phase"] = 0
    _state["phase_name"] = ""
    _state["cost"] = 0.0
    _state["run_dir"] = None
    _state["queue"] = asyncio.Queue()
    _state["loop"] = asyncio.get_event_loop()
    _state["stop_event"] = threading.Event()
    _state["scenario_id"] = req.scenario_id
    _state["model"] = req.model
    _state["execution_profile"] = profile_resolution.profile.name
    _state["execution_profile_policy"] = req.execution_profile
    _state["started_at"] = datetime.now().isoformat()
    _state["phases_done"] = []
    _state["current_devices"] = []
    _state["devices_done"] = []
    _state["deploy_status"] = None
    _state["recent_events"] = []

    thread = threading.Thread(target=_pipeline_thread, args=(req,), daemon=True)
    thread.start()
    return {"status": "started"}


@router.post("/stop")
async def stop_pipeline():
    """Request graceful stop of the running pipeline (stops between phases)."""
    if not _state["running"]:
        raise HTTPException(status_code=400, detail="No pipeline running")
    with _state_lock:
        ev = _state.get("stop_event")
        if ev:
            ev.set()
        _state["stopping"] = True
    return {"status": "stopping"}


@router.get("/status")
def get_status():
    """Return full pipeline state — used by frontend on load to sync UI."""
    return {
        "running": _state["running"],
        "stopping": _state.get("stopping", False),
        "teardown_running": _state.get("teardown_running", False),
        "phase": _state["phase"],
        "phase_name": _state.get("phase_name", ""),
        "cost": round(_state["cost"], 4),
        "scenario_id": _state.get("scenario_id"),
        "model": _state.get("model"),
        "execution_profile": _state.get("execution_profile"),
        "execution_profile_policy": _state.get("execution_profile_policy"),
        "started_at": _state.get("started_at"),
        "deploy_status": _state.get("deploy_status"),
        "phases_done": _state.get("phases_done", []),
        "current_devices": _state.get("current_devices", []),
        "devices_done": _state.get("devices_done", []),
        "run_dir": _state["run_dir"],
        "recent_events": _state.get("recent_events", []),
    }


class BatchRequest(BaseModel):
    batch_ids: list[str]       # e.g. ["1", "2", "3"] or ["all"]
    model: str = "google/gemini-2.0-flash-001"
    provider: str = "openrouter"
    phases: list[int] | None = None
    blind: bool = False        # Deploy each scenario but hide topology from agent
    execution_profile: Literal["auto", "compact", "full"] = "auto"


def _batch_thread(req: BatchRequest):
    """Run multiple scenarios sequentially, pushing events to the shared SSE queue."""
    try:
        from dotenv import load_dotenv
        load_dotenv(ROOT / ".env")

        from src.agent.batch import (
            _aggregate_batch_results,
            _evaluation_metrics,
            _public_scenario_split,
            _parse_scenario_ids,
        )
        # Validate before importing/constructing any execution machinery. This
        # is the worker-side defense if _batch_thread is called directly.
        selector = "all" if req.batch_ids == ["all"] else ",".join(req.batch_ids)
        batch_ids = _parse_scenario_ids(selector)

        from src.agent.provider import LLMProvider
        from src.agent.pipeline import Pipeline
        from src.benchmark.evaluator import evaluate

        def _push(event: dict):
            loop = _state["loop"]
            q = _state["queue"]
            if loop and q:
                loop.call_soon_threadsafe(q.put_nowait, event)
            t = event.get("type")
            if t not in {"__done__", "ping", "text_chunk"}:
                _state["recent_events"].append(event)
                if len(_state["recent_events"]) > _MAX_RECENT_EVENTS:
                    _state["recent_events"] = _state["recent_events"][-_MAX_RECENT_EVENTS:]

        results = []
        evaluation_results = []
        total = len(batch_ids)

        profile_resolution = resolve_execution_profile_for_model(req.execution_profile, req.model)
        _push({"type": "batch_start", "total": total, "ids": batch_ids, "execution_profile": profile_resolution.profile.name, "execution_profile_policy": req.execution_profile})

        for idx, sid in enumerate(batch_ids, 1):
            if _state.get("stop_event") and _state["stop_event"].is_set():
                break

            gt_file = resolve_ground_truth_path(sid)
            scenario_split = _public_scenario_split(sid)
            _push({"type": "batch_scenario_start", "scenario_id": sid, "index": idx, "total": total})
            _state["scenario_id"] = sid

            def make_callback(scenario_id):
                def callback(event: dict):
                    ev = dict(event)
                    ev["batch_scenario_id"] = scenario_id
                    _push(ev)
                    t = ev.get("type")
                    if t == "phase_start":
                        _state["phase"] = ev.get("phase", _state["phase"])
                        _state["phase_name"] = ev.get("agent", "")
                    elif t == "phase_done":
                        cost = ev.get("cost_usd", 0.0)
                        _state["cost"] += cost
                    elif t == "pipeline_done":
                        _state["run_dir"] = ev.get("run_dir")
                return callback

            pipeline = None
            try:
                provider = LLMProvider(provider=req.provider, model=req.model)
                pipeline = Pipeline(
                    provider=provider,
                    phases=req.phases or None,
                    scenario_id=int(sid) if sid.isdigit() else sid,
                    auto_teardown=True,
                    blind=req.blind,
                    benchmark_split=scenario_split,
                    execution_profile=req.execution_profile,
                    manage_scenario=not default_export_store().exists(sid),
                )
                pipeline.run(
                    stream_callback=make_callback(sid),
                    stop_event=_state.get("stop_event"),
                )
            except Exception as exc:
                failed_run_dir = getattr(pipeline, "run_dir", None)
                tracker = getattr(pipeline, "tracker", None)
                cost = round(tracker.total_cost(), 4) if tracker is not None else 0.0
                entry = {
                    "scenario_id": sid,
                    "run_dir": str(failed_run_dir) if failed_run_dir else None,
                    "cost_usd": cost,
                    "metrics": None,
                    "status": "failed",
                    "reason": str(exc),
                }
                results.append(entry)
                _push({
                    "type": "batch_scenario_done",
                    "scenario_id": sid,
                    "index": idx,
                    "total": total,
                    "cost_usd": cost,
                    "metrics": None,
                    "run_dir": entry["run_dir"],
                    "status": "failed",
                    "error": str(exc),
                })
                continue

            run_dir = pipeline.run_dir
            cost = round(pipeline.tracker.total_cost(), 4)

            metrics = None
            evaluation_error = None
            if gt_file.exists():
                try:
                    ev_result = evaluate(run_dir, gt_file, policy="strict-v3")
                    ev_result.split = scenario_split
                    evaluation_results.append(ev_result)
                    metrics = _evaluation_metrics(ev_result)
                except Exception as exc:
                    evaluation_error = str(exc)

            entry = {
                "scenario_id": sid,
                "run_dir": str(run_dir),
                "cost_usd": cost,
                "metrics": metrics,
                "status": "ok" if metrics else "evaluation_failed",
            }
            if evaluation_error:
                entry["reason"] = evaluation_error
            results.append(entry)
            _push({
                "type": "batch_scenario_done",
                "scenario_id": sid,
                "index": idx,
                "total": total,
                "cost_usd": cost,
                "metrics": metrics,
                "run_dir": str(run_dir),
                "status": entry["status"],
            })

        aggregate = _aggregate_batch_results(evaluation_results, results, batch_ids)

        _push({"type": "batch_done", "results": results, "aggregate": aggregate,
               "total_cost_usd": aggregate.get("total_cost_usd", 0)})

    except Exception as exc:
        q = _state["queue"]
        loop = _state["loop"]
        if loop and q:
            loop.call_soon_threadsafe(q.put_nowait, {"type": "error", "message": str(exc)})
    finally:
        with _state_lock:
            _state["running"] = False
            _state["stopping"] = False
        q = _state["queue"]
        loop = _state["loop"]
        if loop and q:
            loop.call_soon_threadsafe(q.put_nowait, {"type": "__done__"})


@router.post("/batch")
async def start_batch(req: BatchRequest):
    """Start a batch run of multiple scenarios sequentially. Returns 409 if already running."""
    from src.agent.batch import SealedScenarioError, _parse_scenario_ids
    try:
        selector = "all" if req.batch_ids == ["all"] else ",".join(req.batch_ids)
        selected_ids = _parse_scenario_ids(selector)
    except SealedScenarioError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    req.batch_ids = selected_ids

    from datetime import datetime
    from src.agent.execution_profiles import resolve_execution_profile_for_model
    profile_resolution = resolve_execution_profile_for_model(
        req.execution_profile, req.model
    )
    with _state_lock:
        if _state["running"]:
            raise HTTPException(status_code=409, detail="Pipeline already running or stopping")
        if _state["teardown_running"]:
            raise HTTPException(status_code=409, detail="Scenario teardown is still running")
        _state["running"] = True
        _state["stopping"] = False
    _state["phase"] = 0
    _state["phase_name"] = ""
    _state["cost"] = 0.0
    _state["run_dir"] = None
    _state["queue"] = asyncio.Queue()
    _state["loop"] = asyncio.get_event_loop()
    _state["stop_event"] = threading.Event()
    _state["scenario_id"] = None
    _state["model"] = req.model
    _state["execution_profile"] = profile_resolution.profile.name
    _state["execution_profile_policy"] = req.execution_profile
    _state["started_at"] = datetime.now().isoformat()
    _state["phases_done"] = []
    _state["current_devices"] = []
    _state["devices_done"] = []
    _state["deploy_status"] = None
    _state["recent_events"] = []

    thread = threading.Thread(target=_batch_thread, args=(req,), daemon=True)
    thread.start()
    return {"status": "batch_started", "total": len(req.batch_ids)}


class TeardownRequest(BaseModel):
    scenario_id: str


@router.post("/teardown")
async def teardown_scenario(req: TeardownRequest):
    """Run 99_teardown.yml for the given scenario in a background thread."""
    from src.agent.batch import SealedScenarioError, _parse_single_scenario_id
    try:
        req.scenario_id = _parse_single_scenario_id(req.scenario_id)
    except SealedScenarioError as exc:
        raise HTTPException(
            status_code=403,
            detail="Sealed scenario teardown is owned by the external controller",
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if default_export_store().exists(req.scenario_id):
        raise HTTPException(
            status_code=400,
            detail="Scenario Lab exports do not own Proxmox resources to tear down",
        )

    with _state_lock:
        if _state["running"]:
            raise HTTPException(
                status_code=409,
                detail="Pipeline is running or stopping — wait for it to finish before teardown",
            )
        if _state["teardown_running"]:
            raise HTTPException(status_code=409, detail="Scenario teardown is already running")
        _state["teardown_running"] = True

    # A completed pipeline may have left its __done__ marker in the old queue
    # after the browser consumed pipeline_done and closed SSE. Always isolate a
    # manual teardown in a fresh queue so its teardown_done event cannot be lost.
    _state["queue"] = asyncio.Queue()
    _state["loop"] = asyncio.get_running_loop()

    def _run():
        cmd = [
            "ansible-playbook",
            "benchmarks/ansible/playbooks/99_teardown.yml",
            "-i", "benchmarks/ansible/inventory.yml",
            "--vault-password-file", "/root/.vault_pass",
            "--extra-vars", f"scenario_id={req.scenario_id}",
        ]
        try:
            try:
                result = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, timeout=300)
                success = result.returncode == 0
                output = (result.stdout + result.stderr).strip()
            except subprocess.TimeoutExpired:
                success = False
                output = "Teardown timeout (300s)"
            except FileNotFoundError:
                success = False
                output = "ansible-playbook not found"

            loop = _state.get("loop")
            q = _state.get("queue")
            if loop and q:
                loop.call_soon_threadsafe(q.put_nowait, {
                    "type": "teardown_done",
                    "scenario_id": req.scenario_id,
                    "success": success,
                    "manual": True,
                    "output": output,
                })
        finally:
            with _state_lock:
                _state["teardown_running"] = False

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return {"status": "teardown_started", "scenario_id": req.scenario_id}


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
