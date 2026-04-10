"""Pipeline route — start pipeline and stream events via SSE (multi-run support)."""
from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

router = APIRouter()

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Multi-run state: { run_id: RunState }
_runs: dict[str, dict[str, Any]] = {}
_runs_lock = threading.Lock()

_MAX_RECENT_EVENTS = 200


def _new_run_state(run_id: str, scenario_id: str | None, model: str) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "running": True,
        "phase": 0,
        "phase_name": "",
        "cost": 0.0,
        "run_dir": None,
        "queue": None,
        "loop": None,
        "stop_event": threading.Event(),
        "scenario_id": scenario_id,
        "model": model,
        "started_at": datetime.now().isoformat(),
        "phases_done": [],
        "current_devices": [],
        "devices_done": [],
        "deploy_status": None,
        "recent_events": [],
    }


class StartRequest(BaseModel):
    model: str = "google/gemini-2.0-flash-001"
    provider: str = "openrouter"
    scenario_id: str | None = None
    phases: list[int] | None = None
    auto_teardown: bool = True
    max_cost_usd: float | None = None
    phase_models: dict[int, str] | None = None
    skip_deploy: bool = False
    # Custom mode fields
    architecture: str | None = None
    posture: str | None = None       # "vulnerable" | "hardened"
    selected_packs: list[str] | None = None
    excluded_vulns: list[str] | None = None  # vuln IDs to exclude from GT


def _pipeline_thread(req: StartRequest, run_id: str):
    """Run the pipeline in a background thread, pushing events to the async queue."""
    state = _runs.get(run_id)
    if not state:
        return
    try:
        from dotenv import load_dotenv
        load_dotenv(ROOT / ".env")

        from src.agent.provider import LLMProvider
        from src.agent.pipeline import Pipeline

        default_model = req.model
        if req.phase_models and req.phases and req.phases[0] in req.phase_models:
            default_model = req.phase_models[req.phases[0]]

        provider = LLMProvider(provider=req.provider, model=default_model)

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
            skip_deploy=req.skip_deploy,
        )

        def callback(event: dict):
            # Tag event with run_id for frontend routing
            event["run_id"] = run_id
            loop = state["loop"]
            q = state["queue"]
            if loop and q:
                loop.call_soon_threadsafe(q.put_nowait, event)
            # Buffer event for page-reload replay
            _skip = {"__done__", "ping", "text_chunk"}
            if event.get("type") not in _skip:
                state["recent_events"].append(event)
                if len(state["recent_events"]) > _MAX_RECENT_EVENTS:
                    state["recent_events"] = state["recent_events"][-_MAX_RECENT_EVENTS:]
            # Update shared state from events
            t = event.get("type")
            if t == "phase_start":
                state["phase"] = event.get("phase", state["phase"])
                state["phase_name"] = event.get("agent", "")
                state["current_devices"] = []
                state["devices_done"] = []
            elif t == "phase_done":
                cost = event.get("cost_usd", 0.0)
                state["cost"] += cost
                state["phases_done"].append({
                    "phase": event.get("phase"),
                    "name": event.get("agent", ""),
                    "cost": cost,
                    "duration_s": event.get("duration_s", 0),
                })
            elif t == "device_start":
                dev = event.get("device_id", "")
                if dev and dev not in state["current_devices"]:
                    state["current_devices"].append(dev)
            elif t == "device_done":
                dev = event.get("device_id", "")
                if dev and dev not in state["devices_done"]:
                    state["devices_done"].append(dev)
            elif t == "deploy_start":
                state["deploy_status"] = "deploying"
            elif t == "deploy_done":
                state["deploy_status"] = "deployed" if event.get("success") else "failed"
            elif t == "pipeline_done":
                state["run_dir"] = event.get("run_dir")
                state["cost"] = event.get("total_cost_usd", state["cost"])

        pipeline.run(stream_callback=callback, stop_event=state["stop_event"])

    except Exception as exc:
        q = state["queue"]
        loop = state["loop"]
        if loop and q:
            loop.call_soon_threadsafe(q.put_nowait, {"type": "error", "run_id": run_id, "message": str(exc)})
    finally:
        state["running"] = False
        q = state["queue"]
        loop = state["loop"]
        if loop and q:
            loop.call_soon_threadsafe(q.put_nowait, {"type": "__done__", "run_id": run_id})


@router.post("/start")
async def start_pipeline(req: StartRequest):
    """Start the pipeline. Returns a unique run_id for tracking."""
    run_id = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    # Ensure unique run_id
    with _runs_lock:
        if run_id in _runs:
            suffix = 1
            while f"{run_id}_{suffix}" in _runs:
                suffix += 1
            run_id = f"{run_id}_{suffix}"

        state = _new_run_state(run_id, req.scenario_id, req.model)
        state["queue"] = asyncio.Queue()
        state["loop"] = asyncio.get_event_loop()
        _runs[run_id] = state

    thread = threading.Thread(target=_pipeline_thread, args=(req, run_id), daemon=True)
    thread.start()
    return {"status": "started", "run_id": run_id}


@router.post("/stop")
async def stop_pipeline(run_id: str | None = None):
    """Request graceful stop. If run_id is None, stops all running pipelines."""
    if run_id:
        state = _runs.get(run_id)
        if not state or not state["running"]:
            raise HTTPException(status_code=400, detail=f"No running pipeline with run_id={run_id}")
        state["stop_event"].set()
        state["running"] = False
        return {"status": "stopping", "run_id": run_id}

    # Stop all running
    stopped = []
    for rid, state in _runs.items():
        if state["running"]:
            state["stop_event"].set()
            state["running"] = False
            stopped.append(rid)
    if not stopped:
        raise HTTPException(status_code=400, detail="No pipeline running")
    return {"status": "stopping", "run_ids": stopped}


@router.get("/status")
def get_status(run_id: str | None = None):
    """Return pipeline state. If run_id given, returns that run; else returns all active runs."""
    if run_id:
        state = _runs.get(run_id)
        if not state:
            raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
        return _state_to_dict(state)

    # Return summary of all runs (active + recent finished)
    return {
        "active_runs": [
            {
                "run_id": s["run_id"],
                "scenario_id": s.get("scenario_id"),
                "model": s.get("model"),
                "phase": s["phase"],
                "phase_name": s.get("phase_name", ""),
                "cost": round(s["cost"], 4),
                "running": s["running"],
                "deploy_status": s.get("deploy_status"),
            }
            for s in _runs.values()
        ]
    }


def _state_to_dict(state: dict) -> dict:
    return {
        "run_id": state["run_id"],
        "running": state["running"],
        "phase": state["phase"],
        "phase_name": state.get("phase_name", ""),
        "cost": round(state["cost"], 4),
        "scenario_id": state.get("scenario_id"),
        "model": state.get("model"),
        "started_at": state.get("started_at"),
        "deploy_status": state.get("deploy_status"),
        "phases_done": state.get("phases_done", []),
        "current_devices": state.get("current_devices", []),
        "devices_done": state.get("devices_done", []),
        "run_dir": state["run_dir"],
        "recent_events": state.get("recent_events", []),
    }


class TeardownRequest(BaseModel):
    scenario_id: str


@router.post("/teardown")
async def teardown_scenario(req: TeardownRequest):
    """Run 99_teardown.yml for the given scenario in a background thread."""
    # Check no pipeline is running for this scenario
    for state in _runs.values():
        if state["running"] and state.get("scenario_id") == req.scenario_id:
            raise HTTPException(status_code=409, detail=f"Pipeline running for scenario {req.scenario_id} — wait for it to finish")

    def _run():
        cmd = [
            "ansible-playbook",
            "benchmarks/ansible/playbooks/99_teardown.yml",
            "-i", "benchmarks/ansible/inventory.yml",
            "--vault-password-file", "/root/.vault_pass",
            "--extra-vars", f"scenario_id={req.scenario_id}",
        ]
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

        # Broadcast teardown event to all active queues
        event = {
            "type": "teardown_done",
            "scenario_id": req.scenario_id,
            "success": success,
            "output": output,
        }
        for state in _runs.values():
            loop = state.get("loop")
            q = state.get("queue")
            if loop and q:
                try:
                    loop.call_soon_threadsafe(q.put_nowait, event)
                except Exception:
                    pass

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return {"status": "teardown_started", "scenario_id": req.scenario_id}


def _get_all_scenario_ids() -> list[str]:
    """Return all non-hardened scenario IDs from benchmarks/scenarios/S*.yaml."""
    scen_dir = ROOT / "benchmarks" / "scenarios"
    try:
        import yaml as _yaml
        ids = []
        for f in sorted(scen_dir.glob("S*.yaml")):
            data = _yaml.safe_load(f.read_text())
            if data.get("posture", "vulnerable") != "hardened":
                ids.append(str(data.get("scenario_id", f.stem)))
        return ids
    except Exception:
        return [str(i) for i in range(1, 11)]


def _run_playbook_for(scenario_id: str, playbook: str, ev_start: str, ev_done: str, callback) -> bool:
    """Run a single Ansible playbook, streaming output line by line via callback."""
    import os
    env = os.environ.copy()
    env["LANG"] = "en_US.UTF-8"
    env["LC_ALL"] = "en_US.UTF-8"
    cmd = [
        "ansible-playbook",
        f"benchmarks/ansible/playbooks/{playbook}",
        "-i", "benchmarks/ansible/inventory.yml",
        "--vault-password-file", "/root/.vault_pass",
        "--extra-vars", f"scenario_id={scenario_id}",
    ]
    callback({"type": ev_start, "scenario_id": scenario_id, "playbook": playbook})
    output_lines: list[str] = []
    success = False
    try:
        proc = subprocess.Popen(
            cmd, cwd=str(ROOT), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                output_lines.append(line)
                callback({"type": "ansible_output", "scenario_id": scenario_id, "playbook": playbook, "line": line})
        proc.wait(timeout=600)
        success = proc.returncode == 0
    except subprocess.TimeoutExpired:
        proc.kill()
        output_lines.append(f"{playbook} timeout (600s)")
    except FileNotFoundError:
        output_lines.append("ansible-playbook not found")
    output = "\n".join(output_lines[-100:])
    callback({"type": ev_done, "scenario_id": scenario_id, "playbook": playbook, "success": success, "output": output})
    return success


@router.post("/start-all")
async def start_all_pipelines(req: StartRequest):
    """Start all scenarios: sequential deploy, then parallel LLM pipelines."""
    scenario_ids = _get_all_scenario_ids()
    loop = asyncio.get_event_loop()
    run_ids: list[str] = []

    with _runs_lock:
        for sid in scenario_ids:
            run_id = datetime.now().strftime("%Y-%m-%d_%H%M%S")
            suffix = 1
            while run_id in _runs or run_id in run_ids:
                run_id = f"{datetime.now().strftime('%Y-%m-%d_%H%M%S')}_{suffix}"
                suffix += 1
            state = _new_run_state(run_id, str(sid), req.model)
            state["queue"] = asyncio.Queue()
            state["loop"] = loop
            _runs[run_id] = state
            run_ids.append(run_id)

    pairs = list(zip(scenario_ids, run_ids))

    def make_callback(run_id: str, state: dict):
        def callback(event: dict):
            event["run_id"] = run_id
            if state["loop"] and state["queue"]:
                state["loop"].call_soon_threadsafe(state["queue"].put_nowait, event)
            skip = {"__done__", "ping", "text_chunk"}
            if event.get("type") not in skip:
                state["recent_events"].append(event)
                if len(state["recent_events"]) > _MAX_RECENT_EVENTS:
                    state["recent_events"] = state["recent_events"][-_MAX_RECENT_EVENTS:]
            t = event.get("type")
            if t == "deploy_start":
                state["deploy_status"] = "deploying"
            elif t == "deploy_done":
                state["deploy_status"] = "deployed" if event.get("success") else "failed"
        return callback

    def _inject_and_verify(sid: str, run_id: str, state: dict):
        """Run 04 + 06 for one scenario (called in parallel threads)."""
        cb = make_callback(run_id, state)
        _run_playbook_for(sid, "04_inject_vulns.yml", "inject_start", "inject_done", cb)
        _run_playbook_for(sid, "06_verify.yml", "verify_start", "verify_done", cb)

    def coordinator():
        # Phase 1 — 03 séquentiel (évite le lock du template LXC)
        for sid, run_id in pairs:
            state = _runs[run_id]
            if state["stop_event"].is_set():
                state["running"] = False
                state["loop"].call_soon_threadsafe(state["queue"].put_nowait, {"type": "__done__", "run_id": run_id})
                continue
            ok = _run_playbook_for(str(sid), "03_deploy_scenario.yml", "deploy_start", "deploy_done", make_callback(run_id, state))
            if not ok:
                state["deploy_status"] = "failed"
                state["running"] = False
                state["loop"].call_soon_threadsafe(state["queue"].put_nowait, {"type": "__done__", "run_id": run_id})

        # Phase 2 — 04 + 06 en parallèle sur tous les scénarios déployés
        inject_threads = []
        for sid, run_id in pairs:
            state = _runs[run_id]
            if not state["running"]:
                continue
            t = threading.Thread(target=_inject_and_verify, args=(str(sid), run_id, state), daemon=True)
            inject_threads.append(t)
            t.start()
        for t in inject_threads:
            t.join()

        # Phase 3 — parallel LLM pipelines (deploy already done)
        threads = []
        for sid, run_id in pairs:
            state = _runs[run_id]
            if not state["running"]:
                continue
            pipeline_req = StartRequest(
                model=req.model,
                provider=req.provider,
                scenario_id=str(sid),
                phases=req.phases,
                auto_teardown=req.auto_teardown,
                max_cost_usd=req.max_cost_usd,
                phase_models=req.phase_models,
                skip_deploy=True,
            )
            t = threading.Thread(target=_pipeline_thread, args=(pipeline_req, run_id), daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

    threading.Thread(target=coordinator, daemon=True).start()
    return {"status": "started", "run_ids": run_ids, "scenario_ids": scenario_ids}


@router.get("/stream")
async def stream_events(run_id: str | None = None):
    """SSE endpoint — streams events for a specific run or all runs."""
    if run_id:
        state = _runs.get(run_id)
        if not state:
            raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
        q = state.get("queue")
        if q is None:
            raise HTTPException(status_code=400, detail="No active pipeline run")

        async def generator():
            while True:
                try:
                    event = await asyncio.wait_for(q.get(), timeout=30.0)
                except asyncio.TimeoutError:
                    yield {"event": "ping", "data": "{}"}
                    continue
                if event.get("type") == "__done__":
                    break
                yield {"data": json.dumps(event)}
                if event.get("type") in ("pipeline_done", "error"):
                    break

        return EventSourceResponse(generator())

    # Stream from all active runs (multiplexed)
    # Create a shared queue that aggregates all run events
    shared_q: asyncio.Queue = asyncio.Queue()
    loop = asyncio.get_event_loop()

    # Subscribe to all existing run queues
    active_runs = {rid: s for rid, s in _runs.items() if s["running"]}
    if not active_runs:
        raise HTTPException(status_code=400, detail="No active pipeline runs")

    # Relay events from each run's queue to shared queue
    done_count = 0
    expected = len(active_runs)

    async def relay(source_q: asyncio.Queue):
        nonlocal done_count
        while True:
            try:
                event = await asyncio.wait_for(source_q.get(), timeout=30.0)
            except asyncio.TimeoutError:
                continue
            await shared_q.put(event)
            if event.get("type") in ("__done__", "pipeline_done", "error"):
                done_count += 1
                if done_count >= expected:
                    await shared_q.put({"type": "__done__"})
                break

    for rid, s in active_runs.items():
        q = s.get("queue")
        if q:
            asyncio.ensure_future(relay(q))

    async def generator():
        while True:
            try:
                event = await asyncio.wait_for(shared_q.get(), timeout=30.0)
            except asyncio.TimeoutError:
                yield {"event": "ping", "data": "{}"}
                continue
            if event.get("type") == "__done__":
                break
            yield {"data": json.dumps(event)}

    return EventSourceResponse(generator())
