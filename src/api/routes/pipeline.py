"""Pipeline route — start pipeline and stream events via SSE."""
from __future__ import annotations

import asyncio
import json
import math
import subprocess
import sys
import threading
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4
from typing import Any, Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, field_validator, model_validator
from src.agent.provider import validate_provider_choice
from sse_starlette.sse import EventSourceResponse

from src.benchmark.scenario_exports import default_export_store, resolve_ground_truth_path
from src.benchmark.scenario_deployment import GeneratedScenarioDeployment
from src.agent.batch_outcomes import batch_run_status
from src.benchmark.lab_lock import reserve_lab
from src.api.run_coordinator import RunCoordinator

router = APIRouter()

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Global pipeline state (single concurrent run)
_state: dict[str, Any] = {
    "running": False,
    "lab_waiting": False,
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
    "runner_kind": "lance",
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
_coordinator = RunCoordinator(_state_lock)


def _lab_event(event: dict, *, publish: bool = False) -> None:
    _coordinator.lab_event(_state, event, publish=publish)


class ModelSelection(BaseModel):
    model: str = Field(min_length=1)
    provider: str = Field(min_length=1)

    @field_validator("provider")
    @classmethod
    def supported_provider(cls, value: str) -> str:
        return validate_provider_choice(value)


class StartRequest(BaseModel):
    @model_validator(mode="before")
    @classmethod
    def reject_cli_only_experiment(cls, value):
        if isinstance(value, dict) and set(value) & {"decision_policy", "experiment_scope", "audit_inventory"}:
            raise ValueError("Inventory policy experiments are CLI-only")
        return value

    runner_kind: Literal["lance", "vanilla", "scripted"] = "lance"
    model: str | None = None
    provider: str | None = None
    script_id: str | None = None
    max_tool_calls: int | None = Field(default=None, ge=1)
    max_duration_s: float | None = Field(default=None, gt=0)

    @field_validator("provider")
    @classmethod
    def supported_provider(cls, value: str | None) -> str | None:
        return validate_provider_choice(value) if value else None

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

    @model_validator(mode="after")
    def validate_runner_contract(self):
        if self.runner_kind == "vanilla" and not (self.model and self.provider):
            raise ValueError("This runner requires an explicit provider and model")
        if self.runner_kind == "lance":
            if not self.deploy_only and not (self.model and self.provider):
                raise ValueError("This runner requires an explicit provider and model")
            if self.deploy_only and bool(self.model) != bool(self.provider):
                raise ValueError("Deployment requires either both provider and model or neither")
            if self.script_id is not None:
                raise ValueError("script_id is only valid for the scripted runner")
            if self.max_tool_calls is not None or self.max_duration_s is not None:
                raise ValueError("Action/time budgets are only available for vanilla and scripted runners")
            return self

        offline_smoke = self.runner_kind == "scripted" and self.script_id == "smoke-v1"
        if offline_smoke:
            if self.target_network is not None:
                raise ValueError("smoke-v1 is offline and does not accept target_network")
            if self.max_tool_calls is not None or self.max_cost_usd is not None:
                raise ValueError("smoke-v1 does not use tools or a model budget")
        else:
            if not self.target_network or "/" not in self.target_network:
                raise ValueError("Vanilla and discovery-v1 require an explicit target_network CIDR")
            try:
                from src.agent.run_modes import validate_target_network
                validate_target_network(self.target_network)
            except ValueError as exc:
                raise ValueError(str(exc)) from exc
        if any((
            self.scenario_id is not None,
            self.phases is not None,
            self.deploy_only,
            self.blind,
            self.architecture is not None,
            self.posture is not None,
            self.selected_packs is not None,
            self.excluded_vulns is not None,
            self.phase_models is not None,
            self.auto_teardown is False,
        )):
            raise ValueError("Vanilla and scripted runners do not accept scenario or deployment settings")
        if self.runner_kind == "vanilla" and self.script_id is not None:
            raise ValueError("script_id is only valid for the scripted runner")
        if self.runner_kind == "scripted" and (self.provider is not None or self.model is not None):
            raise ValueError("The scripted runner does not use a provider or model")
        if self.execution_profile != "auto":
            raise ValueError("Execution profiles apply only to the LANCE runner")
        if self.max_tool_calls is not None and self.max_tool_calls > 100:
            raise ValueError("max_tool_calls must be between 1 and 100")
        if self.max_duration_s is not None and self.max_duration_s > 3600:
            raise ValueError("max_duration_s must be between 0 and 3600")
        if self.max_cost_usd is not None and (not math.isfinite(self.max_cost_usd) or self.max_cost_usd <= 0):
            raise ValueError("max_cost_usd must be positive")
        if self.runner_kind == "scripted":
            from src.agent.run_modes import SCRIPT_IDS
            if self.script_id not in SCRIPT_IDS:
                raise ValueError(f"script_id must be one of: {', '.join(sorted(SCRIPT_IDS))}")
        return self


def _write_private_json(path: Path, payload: dict[str, Any]) -> None:
    """Write a post-run evaluation artifact without exposing it to the agent."""
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def _evaluate_single_run(pipeline: Any, req: StartRequest) -> dict[str, Any]:
    """Evaluate a completed dashboard run and persist a private evaluation summary.

    The pipeline deliberately keeps the oracle unavailable during all agent
    phases. This function is called only after ``Pipeline.run`` has returned,
    so generated ground truth can safely be used here as well.
    """
    run_dir = Path(pipeline.run_dir)
    scenario_id = req.scenario_id
    base_event: dict[str, Any] = {
        "type": "evaluation_done",
        "scenario_id": scenario_id,
        "run_dir": str(run_dir),
        "metrics": None,
    }

    def finish(
        status: str,
        *,
        reason: str | None = None,
        metrics: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        event = {**base_event, "status": status, "metrics": metrics}
        if reason:
            event["reason"] = reason
        summary = {
            "schema_version": 1,
            "status": status,
            "scenario_id": scenario_id,
            "split": getattr(pipeline, "benchmark_split", None),
            "policy": "strict-v3",
            "metrics": metrics,
        }
        if reason:
            summary["reason"] = reason
        _write_private_json(run_dir / "evaluation_summary.json", summary)
        try:
            pipeline._update_run_meta({
                "evaluation": {
                    "status": status,
                    "metrics": metrics,
                    **({"reason": reason} if reason else {}),
                }
            })
        except Exception:
            # Evaluation reporting must never turn a completed run into a
            # failed pipeline if metadata persistence is unavailable.
            pass
        return event

    if scenario_id is None:
        return finish("skipped", reason="No benchmark scenario selected")

    if req.architecture:
        # Custom dashboard scenarios generate their oracle in the run directory
        # only after all agent phases have completed.
        ground_truth = run_dir / "ground_truth.yaml"
    else:
        ground_truth = resolve_ground_truth_path(scenario_id)

    if not ground_truth.is_file():
        return finish("skipped", reason=f"Ground truth not found: {ground_truth}")

    vuln_file = run_dir / "03_vuln_analysis.json"
    if not vuln_file.is_file():
        return finish("skipped", reason="03_vuln_analysis.json not found")

    try:
        from src.agent.batch import _evaluation_metrics
        from src.benchmark.evaluator import evaluate

        result = evaluate(run_dir, ground_truth, policy="strict-v3")
        result.split = getattr(pipeline, "benchmark_split", None)
        metrics = _evaluation_metrics(result)
        _write_private_json(run_dir / "evaluation.json", asdict(result))
        return finish("completed", metrics=metrics)
    except Exception as exc:
        return finish("failed", reason=f"Evaluation failed: {exc}")


def _pipeline_thread(req: StartRequest):
    """Run the pipeline in a background thread, pushing events to the async queue."""
    try:
        from dotenv import load_dotenv
        load_dotenv(ROOT / ".env")

        from src.agent.provider import LLMProvider
        from src.agent.run_modes import make_runner

        # If phase_models is provided, we'll instantiate providers dynamically in Pipeline
        # but we need a default one for the init and cost tracking setup
        default_model = req.model
        if req.phase_models and req.phases and req.phases[0] in req.phase_models:
            default_model = req.phase_models[req.phases[0]]

        if req.deploy_only and not (req.provider and req.model):
            # Pipeline accepts a provider object during construction, while
            # deploy-only never calls it.  Keep deployment independent of model
            # configuration without opening a provider connection.
            provider = SimpleNamespace(provider="", model="")
        else:
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

        pipeline = make_runner(
            "lance",
            provider=provider,
            phases=req.phases or None,
            scenario_id=req.scenario_id,
            auto_teardown=req.auto_teardown,
            max_cost_usd=req.max_cost_usd,
            phase_models=req.phase_models,
            custom_config=custom_config,
            manage_scenario=True,
            target_network=req.target_network,
            blind=req.blind,
            execution_profile=req.execution_profile,
        )

        pending_pipeline_done: dict[str, Any] | None = None
        release_pipeline_done = False

        def callback(event: dict):
            nonlocal pending_pipeline_done
            _lab_event(event)
            # Evaluation must happen before pipeline_done reaches the browser;
            # the frontend closes the SSE stream as soon as it receives that
            # event. Keep the original event until evaluation is complete.
            if event.get("type") == "pipeline_done" and not req.deploy_only and not release_pipeline_done:
                pending_pipeline_done = dict(event)
                _state["run_dir"] = event.get("run_dir")
                _state["cost"] = event.get("total_cost_usd", _state["cost"])
                return
            _coordinator.publish(_state, event)

        if req.deploy_only:
            pipeline.run_deploy_only(stream_callback=callback, stop_event=_state["stop_event"])
        else:
            run_results = pipeline.run(stream_callback=callback, stop_event=_state["stop_event"])
            evaluation_event = _evaluate_single_run(pipeline, req)
            callback(evaluation_event)

            if pending_pipeline_done is None:
                pending_pipeline_done = {
                    "type": "pipeline_done",
                    "results": run_results,
                    "total_cost_usd": round(pipeline.tracker.total_cost(), 4),
                    "run_dir": str(pipeline.run_dir),
                }
            pending_pipeline_done.update({
                "evaluation_status": evaluation_event["status"],
                "metrics": evaluation_event.get("metrics"),
            })
            if evaluation_event.get("reason"):
                pending_pipeline_done["evaluation_error"] = evaluation_event["reason"]
            release_pipeline_done = True
            callback(pending_pipeline_done)

    except Exception as exc:
        _coordinator.publish(_state, {"type": "error", "message": str(exc)})
    finally:
        _coordinator.finish(_state)


def _simple_runner_thread(req: StartRequest):
    """Run a bounded non-benchmark runner through the common execution contract."""
    seen_terminal = False
    try:
        from dotenv import load_dotenv
        load_dotenv(ROOT / ".env")
        from src.agent.provider import LLMProvider
        from src.agent.run_modes import make_runner

        provider = LLMProvider(provider=req.provider, model=req.model) if req.runner_kind == "vanilla" else None
        runner = make_runner(
            req.runner_kind,
            provider=provider,
            target_network=req.target_network,
            max_cost_usd=req.max_cost_usd,
            max_tool_calls=req.max_tool_calls,
            max_duration_s=req.max_duration_s,
            script_id=req.script_id,
            execution_profile=req.execution_profile,
        )
        def callback(event: dict):
            nonlocal seen_terminal
            _lab_event(event)
            if event.get("type") in {"pipeline_done", "runner_done"}:
                seen_terminal = True
            _coordinator.publish(_state, event)

        result = runner.run(stream_callback=callback, stop_event=_state["stop_event"])
        if not seen_terminal:
            tracker = getattr(runner, "tracker", None)
            callback({
                "type": "runner_done",
                "runner_kind": req.runner_kind,
                "status": result.get("status", "completed") if isinstance(result, dict) else "completed",
                "result": result,
                "run_dir": str(runner.run_dir),
                "total_cost_usd": round(tracker.total_cost(), 4) if tracker else 0.0,
            })
    except Exception as exc:
        if not seen_terminal:
            _coordinator.publish(_state, {"type": "error", "message": str(exc)})
    finally:
        _coordinator.finish(_state)


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
                    "Sealed scenarios require the external controller and isolated worker. "
                    "They cannot run inside the dashboard process."
                ),
            ) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    profile_name = None
    profile_policy = None
    if req.runner_kind == "lance":
        from src.agent.execution_profiles import resolve_execution_profile_for_model
        resolution = resolve_execution_profile_for_model(req.execution_profile, req.model)
        profile_name = resolution.profile.name
        profile_policy = req.execution_profile
    try:
        _coordinator.begin(
            _state,
            loop=asyncio.get_running_loop(),
            runner_kind=req.runner_kind,
            scenario_id=req.scenario_id,
            model=req.model,
            execution_profile=profile_name,
            execution_profile_policy=profile_policy,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    target = _pipeline_thread if req.runner_kind == "lance" else _simple_runner_thread
    thread = threading.Thread(target=target, args=(req,), daemon=True)
    try:
        thread.start()
    except Exception:
        _coordinator.finish(_state)
        raise
    return {"status": "started"}


@router.post("/stop")
async def stop_pipeline():
    """Request graceful stop of the running pipeline (stops between phases)."""
    if not _coordinator.request_stop(_state):
        raise HTTPException(status_code=400, detail="No pipeline running")
    return {"status": "stopping"}


@router.get("/status")
def get_status():
    """Return full pipeline state — used by frontend on load to sync UI."""
    return _coordinator.status(_state)


class BatchRequest(ModelSelection):
    batch_ids: list[str]       # e.g. ["1", "2", "3"] or ["all"]
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
            _parse_scenario_ids,
            _phase5_summary,
        )
        from src.agent.execution_profiles import resolve_execution_profile_for_model
        from src.benchmark.scenario_exports import resolve_scenario_split
        # Validate before importing/constructing any execution machinery. This
        # is the worker-side defense if _batch_thread is called directly.
        selector = "all" if req.batch_ids == ["all"] else ",".join(req.batch_ids)
        batch_ids = _parse_scenario_ids(selector)

        from src.agent.provider import LLMProvider
        from src.agent.run_modes import make_runner
        from src.benchmark.evaluator import evaluate

        def _push(event: dict):
            _lab_event(event)
            _coordinator.publish(_state, event, track_progress=False)

        results = []
        evaluation_results = []
        total = len(batch_ids)
        batch_id = f"batch-{uuid4().hex[:12]}"

        profile_resolution = resolve_execution_profile_for_model(req.execution_profile, req.model)
        _push({
            "type": "batch_start",
            "batch_id": batch_id,
            "total": total,
            "ids": batch_ids,
            "execution_profile": profile_resolution.profile.name,
            "execution_profile_policy": req.execution_profile,
        })

        for idx, sid in enumerate(batch_ids, 1):
            if _state.get("stop_event") and _state["stop_event"].is_set():
                break

            gt_file = resolve_ground_truth_path(sid)
            benchmark_split = resolve_scenario_split(sid)
            _push({
                "type": "batch_scenario_start",
                "batch_id": batch_id,
                "scenario_id": sid,
                "index": idx,
                "total": total,
            })
            _state["scenario_id"] = sid

            def make_callback(scenario_id):
                def callback(event: dict):
                    ev = dict(event)
                    ev["batch_id"] = batch_id
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
                pipeline = make_runner(
                    "lance",
                    provider=provider,
                    phases=req.phases or None,
                    scenario_id=int(sid) if sid.isdigit() else sid,
                    auto_teardown=True,
                    blind=req.blind,
                    benchmark_split=benchmark_split,
                    execution_profile=req.execution_profile,
                    manage_scenario=True,
                )
                run_results = pipeline.run(
                    stream_callback=make_callback(sid),
                    stop_event=_state.get("stop_event"),
                )
                try:
                    pipeline._update_run_meta({
                        "batch": {
                            "batch_id": batch_id,
                            "batch_index": idx,
                            "batch_total": total,
                            "scenario_id": sid,
                        }
                    })
                except Exception:
                    pass
            except Exception as exc:
                failed_run_dir = getattr(pipeline, "run_dir", None)
                tracker = getattr(pipeline, "tracker", None)
                cost = round(tracker.total_cost(), 4) if tracker is not None else 0.0
                entry = {
                    "batch_id": batch_id,
                    "batch_index": idx,
                    "batch_total": total,
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
                    "batch_id": batch_id,
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
                    ev_result.split = benchmark_split
                    evaluation_results.append(ev_result)
                    metrics = _evaluation_metrics(ev_result)
                except Exception as exc:
                    evaluation_error = str(exc)

            phase5 = _phase5_summary(run_dir, run_results)
            entry = {
                "batch_id": batch_id,
                "batch_index": idx,
                "batch_total": total,
                "scenario_id": sid,
                "run_dir": str(run_dir),
                "pipeline_results": run_results,
                "phase5": phase5,
                "phase5_status": phase5["status"],
                "cost_usd": cost,
                "metrics": metrics,
                "status": batch_run_status(run_dir, run_results,
                    phase5_status=phase5["status"], evaluated=bool(metrics)),
            }
            if evaluation_error:
                entry["reason"] = evaluation_error
            results.append(entry)
            _push({
                "type": "batch_scenario_done",
                "batch_id": batch_id,
                "scenario_id": sid,
                "index": idx,
                "total": total,
                "cost_usd": cost,
                "metrics": metrics,
                "run_dir": str(run_dir),
                "status": entry["status"],
            })

        aggregate = _aggregate_batch_results(evaluation_results, results, batch_ids)

        _push({
            "type": "batch_done",
            "batch_id": batch_id,
            "results": results,
            "aggregate": aggregate,
            "total_cost_usd": aggregate.get("total_cost_usd", 0),
        })

    except Exception as exc:
        _coordinator.publish(_state, {"type": "error", "message": str(exc)})
    finally:
        _coordinator.finish(_state)


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

    from src.agent.execution_profiles import resolve_execution_profile_for_model
    profile_resolution = resolve_execution_profile_for_model(
        req.execution_profile, req.model
    )
    try:
        _coordinator.begin(
            _state,
            loop=asyncio.get_running_loop(),
            runner_kind="lance",
            scenario_id=None,
            model=req.model,
            execution_profile=profile_resolution.profile.name,
            execution_profile_policy=req.execution_profile,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    thread = threading.Thread(target=_batch_thread, args=(req,), daemon=True)
    try:
        thread.start()
    except Exception:
        _coordinator.finish(_state)
        raise
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

    try:
        _coordinator.begin_teardown(
            _state, scenario_id=req.scenario_id, loop=asyncio.get_running_loop()
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    def _run_locked():
        deployment = GeneratedScenarioDeployment.from_lease(req.scenario_id)
        exported = default_export_store().exists(req.scenario_id)
        cmd = [
            "ansible-playbook",
            "benchmarks/ansible/playbooks/99_teardown.yml",
            "-i", "benchmarks/ansible/inventory.yml",
            "--vault-password-file", "/root/.vault_pass",
            "--extra-vars", f"scenario_id={req.scenario_id}",
        ]
        try:
            if exported and deployment is None:
                success = False
                output = "Aucun lease de déploiement actif pour cet export Scenario Lab"
            else:
                if deployment is not None:
                    cmd.extend(["--extra-vars", f"@{deployment.overlay_path}"])
                    source_scenario_id = deployment.source_scenario_id
                else:
                    source_scenario_id = str(req.scenario_id)
                cmd.extend(["--extra-vars", f"source_scenario_id={source_scenario_id}"])
                result = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, timeout=300)
                success = result.returncode == 0
                output = (result.stdout + result.stderr).strip()
        except subprocess.TimeoutExpired:
            success = False
            output = "Teardown timeout (300s)"
        except FileNotFoundError:
            success = False
            output = "ansible-playbook not found"

        if success and deployment is not None:
            deployment.release()
        _coordinator.enqueue(_state, {
            "type": "teardown_done",
            "scenario_id": req.scenario_id,
            "success": success,
            "manual": True,
            "output": output,
        })

    def _run():
        try:
            with reserve_lab(callback=lambda event: _lab_event(event, publish=True)):
                _run_locked()
        except Exception as exc:
            _coordinator.enqueue(_state, {
                "type": "teardown_done", "scenario_id": req.scenario_id,
                "success": False, "manual": True, "output": str(exc),
            })
        finally:
            _coordinator.finish_teardown(_state)

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
            # Sub-pipeline completion and errors can be followed by evaluation,
            # teardown and further scenarios. Only the worker owns stream end.
            if event.get("type") == "teardown_done" and event.get("manual") is True:
                break

    return EventSourceResponse(generator())
