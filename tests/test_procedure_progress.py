"""Procedure launch contracts, durable controller progress and protected reads."""
from __future__ import annotations

import json
import threading
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest
from pydantic import ValidationError

from src.agent.procedure_progress import RulesProcedureProgress
from src.agent.procedures import get_procedure
from src.api.routes import pipeline, runs


def _step(snapshot, identifier):
    return next(item for item in snapshot["steps"] if item["id"] == identifier)


def test_preparation_requires_verification_and_ignores_unidentified_teardown(tmp_path):
    progress = RulesProcedureProgress(tmp_path, auto_teardown=True)
    assert progress.observe({"type": "lab_waiting"})["status"] == "waiting"
    assert progress.observe({"type": "lab_acquired"})["status"] == "running"
    assert progress.observe({"type": "teardown_start", "scenario_id": "another"}) is None
    assert _step(progress.data, "cleanup")["status"] == "pending"
    progress.observe({"type": "deploy_start"})
    progress.observe({"type": "deploy_done", "success": True})
    assert _step(progress.data, "deployment")["status"] == "running"
    progress.observe({"type": "inject_done", "success": True})
    assert _step(progress.data, "deployment")["status"] == "running"
    snapshot = progress.observe({"type": "verify_done", "success": False})
    assert _step(snapshot, "deployment")["status"] == "failed"
    assert json.loads((tmp_path / "procedure_progress.json").read_text()) == snapshot


def test_observed_initial_cleanup_is_preparation_even_without_final_cleanup(tmp_path):
    progress = RulesProcedureProgress(tmp_path, auto_teardown=False)
    context = {"scenario_id": "2", "playbook": "99_teardown.yml", "attempt": 1}
    snapshot = progress.observe({"type": "teardown_start", **context})
    assert snapshot["status"] == "running"
    assert _step(snapshot, "deployment")["status"] == "running"
    assert _step(snapshot, "deployment")["reason"] == "predeployment_cleanup"
    assert _step(snapshot, "cleanup")["status"] == "pending"
    snapshot = progress.observe({"type": "teardown_done", **context, "success": True})
    assert _step(snapshot, "deployment")["status"] == "running"
    assert _step(snapshot, "cleanup")["status"] == "pending"
    snapshot = progress.observe({"type": "verify_done", "success": True})
    assert _step(snapshot, "deployment")["status"] == "completed"


def test_failed_initial_cleanup_is_not_hidden_by_later_preflight_success(tmp_path):
    progress = RulesProcedureProgress(tmp_path, auto_teardown=False)
    context = {"scenario_id": "2", "playbook": "99_teardown.yml", "attempt": 1}
    progress.observe({"type": "teardown_start", **context})
    snapshot = progress.observe({"type": "teardown_done", **context, "success": False})
    assert _step(snapshot, "deployment")["status"] == "failed"
    assert _step(snapshot, "cleanup")["status"] == "pending"
    progress.observe({"type": "deploy_start"})
    progress.observe({"type": "deploy_done", "success": True})
    snapshot = progress.observe({"type": "verify_done", "success": True})
    assert _step(snapshot, "deployment")["status"] == "partial"
    assert _step(snapshot, "deployment")["reason"] == "predeployment_cleanup_failed"
    snapshot = progress.observe({"type": "pipeline_done", "status": "completed"}, terminal=True)
    assert _step(snapshot, "deployment")["status"] == "partial"
    assert _step(snapshot, "cleanup")["status"] == "skipped"
    assert json.loads((tmp_path / "procedure_progress.json").read_text()) == snapshot


def test_initial_cleanup_without_an_observed_result_does_not_complete_preparation(tmp_path):
    progress = RulesProcedureProgress(tmp_path, auto_teardown=True)
    snapshot = progress.observe({"type": "teardown_done", "playbook": "99_teardown.yml"})
    assert _step(snapshot, "deployment")["status"] == "not_observed"
    assert _step(snapshot, "cleanup")["status"] == "pending"


def test_partial_checks_are_not_upgraded_by_successful_pipeline_terminal(tmp_path):
    progress = RulesProcedureProgress(tmp_path, auto_teardown=False)
    progress.observe({"type": "verify_done", "success": True})
    progress.observe({"type": "phase_done", "phase": 3, "status": "completed_with_device_errors"})
    progress.observe({"type": "phase_done", "phase": 4, "status": "completed"})
    (tmp_path / "run_summary.md").write_text("# Saved observations\n")
    snapshot = progress.observe({"type": "pipeline_done", "status": "completed"}, terminal=True)
    assert snapshot["status"] == "completed" and snapshot["controls_complete"] is False
    assert _step(snapshot, "analysis")["status"] == "partial"
    assert _step(snapshot, "cleanup")["status"] == "skipped"
    assert _step(snapshot, "results")["status"] == "completed"


@pytest.mark.parametrize("status", ["failed", "stopped", "budget_exceeded"])
def test_terminal_never_invents_finished_checks_or_instant_cleanup(tmp_path, status):
    progress = RulesProcedureProgress(tmp_path, auto_teardown=True)
    progress.observe({"type": "deploy_start"})
    progress.observe({"type": "teardown_start"})
    assert progress.data["status"] == "running"
    assert _step(progress.data, "cleanup")["status"] == "running"
    snapshot = progress.observe({"type": "pipeline_done", "status": status}, terminal=True)
    expected = "failed" if status == "failed" else "stopped"
    assert _step(snapshot, "cleanup")["status"] == expected
    assert _step(snapshot, "analysis")["status"] == "not_observed"
    assert _step(snapshot, "verification")["status"] == "not_observed"
    assert _step(snapshot, "results")["status"] == "not_observed"
    assert snapshot["controls_complete"] is False


def test_cleanup_failure_and_snapshot_version_are_preserved(tmp_path, monkeypatch):
    progress = RulesProcedureProgress(tmp_path, auto_teardown=True)
    descriptor = dict(progress.data["procedure"])
    progress.observe({"type": "verify_done", "success": True})
    progress.observe({"type": "teardown_start"})
    progress.observe({"type": "teardown_done", "success": False})
    monkeypatch.setattr("src.agent.procedure_progress.get_procedure", lambda _: pytest.fail("Descriptor changed during run"))
    snapshot = progress.observe({"type": "pipeline_done", "status": "partial"}, terminal=True)
    assert _step(snapshot, "cleanup")["status"] == "failed"
    assert snapshot["procedure"] == descriptor


def test_new_inventory_start_contract_accepts_only_catalogued_code():
    request = pipeline.StartRequest(runner_kind="scripted", script_id="service-inventory-v1",
                                    target_network="192.0.2.0/24")
    assert request.script_id == "service-inventory-v1"
    # Runner-specific catalogue defaults are resolved by make_runner.
    assert request.max_tool_calls is request.max_duration_s is None
    for identifier in ("/tmp/arbitrary.py", "python -c print(1)", "unknown"):
        with pytest.raises(ValidationError):
            pipeline.StartRequest(runner_kind="scripted", script_id=identifier, target_network="192.0.2.0/24")


@pytest.fixture
def procedure_api(tmp_path, monkeypatch):
    monkeypatch.setattr(runs, "OUTPUT_DIR", tmp_path)
    app = FastAPI()
    app.include_router(runs.router, prefix="/api/runs")
    with TestClient(app) as client:
        yield client, tmp_path


def _script_run(root, identifier="service-inventory-v1"):
    directory = root / "procedure-run"
    directory.mkdir()
    network = None if identifier == "smoke-v1" else "192.0.2.0/24"
    descriptor = get_procedure(identifier)
    result = {
        "schema_version": 1, "script_id": identifier, "status": "completed", "target_network": network,
        "procedure": {key: descriptor[key] for key in ("id", "title", "version", "fingerprint")},
        "hosts": [], "counts": {"hosts": 0, "services": 0}, "coverage": {"partial": False},
        "steps": [{"id": "results", "label": "Observations saved", "status": "completed"}],
        "errors": [], "evidence_refs": [],
    }
    (directory / "run_meta.json").write_text(json.dumps({"runner_kind": "scripted", "script_id": identifier,
                                                        "target_network": network, "status": "completed"}))
    (directory / "procedure_results.json").write_text(json.dumps(result))
    return directory, result


@pytest.mark.parametrize("identifier,kind", [("service-inventory-v1", "inventory"), ("smoke-v1", "diagnostic")])
def test_procedure_results_return_the_executed_snapshot(procedure_api, monkeypatch, identifier, kind):
    client, root = procedure_api
    directory, result = _script_run(root, identifier)
    result["procedure"]["version"] = "0.9.0"
    result["procedure"]["fingerprint"] = "a" * 64
    (directory / "procedure_results.json").write_text(json.dumps(result))
    monkeypatch.setattr("src.agent.procedures.get_procedure", lambda _: pytest.fail("Current descriptor substituted"))
    response = client.get("/api/runs/procedure-run/procedure-results")
    assert response.status_code == 200
    data = response.json()
    assert data["available"] is True and data["kind"] == kind
    assert data["procedure"] == result["procedure"]


def test_historical_missing_artifact_is_explicitly_unavailable(procedure_api):
    client, root = procedure_api
    directory, _ = _script_run(root)
    (directory / "procedure_results.json").unlink()
    result = client.get("/api/runs/procedure-run/procedure-results")
    assert result.status_code == 200
    assert result.json() == {"schema_version": 1, "available": False, "reason": "procedure_results_not_recorded",
                             "status": "done"}


def test_inventory_waiting_for_laboratory_is_a_valid_readable_state(procedure_api):
    client, root = procedure_api
    directory, result = _script_run(root)
    result["status"] = "waiting"
    (directory / "procedure_results.json").write_text(json.dumps(result))
    response = client.get("/api/runs/procedure-run/procedure-results")
    assert response.status_code == 200
    assert response.json()["results"]["status"] == "waiting"


def test_sealed_runs_and_symlinked_runs_or_artifacts_are_not_exposed(procedure_api, tmp_path):
    client, root = procedure_api
    directory, _ = _script_run(root)
    metadata = json.loads((directory / "run_meta.json").read_text())
    metadata["benchmark_split"] = "eval-sealed"
    (directory / "run_meta.json").write_text(json.dumps(metadata))
    assert client.get("/api/runs/procedure-run/procedure-results").status_code == 403
    metadata.pop("benchmark_split")
    (directory / "run_meta.json").write_text(json.dumps(metadata))
    source = directory / "procedure_results.json"
    outside = root / "outside.json"
    source.replace(outside)
    source.symlink_to(outside)
    assert client.get("/api/runs/procedure-run/procedure-results").status_code == 404
    (root / "symlink-run").symlink_to(directory, target_is_directory=True)
    assert client.get("/api/runs/symlink-run/procedure-results").status_code == 404
    assert client.get("/api/runs/invalid%2Fid/procedure-results").status_code == 404


@pytest.mark.parametrize("mutation", [
    lambda result: result.update(schema_version=2),
    lambda result: result.update(status={"label": "completed"}),
    lambda result: result.update(script_id=[]),
    lambda result: result.update(steps=[{"id": "x", "label": "x", "status": []}]),
    lambda result: result.update(counts={"hosts": -1}),
    lambda result: result.update(target_network="198.51.100.0/24"),
    lambda result: result.update(hosts=[{"ip": "198.51.100.1", "status": "up", "services": []}]),
    lambda result: result.update(hosts=[{"ip": "192.0.2.1", "status": [], "services": []}]),
    lambda result: result.update(hosts=[{"ip": "192.0.2.1", "status": "up", "services": [{"port": "22", "protocol": "tcp", "state": "open"}]}]),
])
def test_malformed_script_observations_fail_closed(procedure_api, mutation):
    client, root = procedure_api
    directory, result = _script_run(root)
    mutation(result)
    (directory / "procedure_results.json").write_text(json.dumps(result))
    assert client.get("/api/runs/procedure-run/procedure-results").status_code == 422


@pytest.mark.parametrize("contents,status", [("[]", 422), ("{broken", 422), ('{"status":NaN}', 422), ('{"status":1e999}', 422), (" " * (runs._PROCEDURE_JSON_LIMIT + 1), 413)])
def test_nonobject_invalid_and_oversized_artifacts_are_rejected(procedure_api, contents, status):
    client, root = procedure_api
    directory, _ = _script_run(root)
    (directory / "procedure_results.json").write_text(contents)
    assert client.get("/api/runs/procedure-run/procedure-results").status_code == status


def test_rules_results_reuse_common_evidence_and_keep_legacy_progress_unknown(procedure_api):
    client, root = procedure_api
    directory = root / "rules-run"
    directory.mkdir()
    files = {
        "run_meta.json": {"runner_kind": "rules", "status": "completed"},
        "audit_topology.json": {"nodes": [{"id": "web", "ip": "192.0.2.10"}], "edges": []},
        "03_vuln_analysis.json": {"vulnerabilities": [{"id": "V1", "device_id": "web", "device_ip": "192.0.2.10", "type": "directory_listing", "service": "http", "port": 80}]},
        "04_exploitation.json": {"tests": [{"vuln_id": "V1", "status": "CONFIRMED"}]},
    }
    for filename, value in files.items():
        (directory / filename).write_text(json.dumps(value))
    response = client.get("/api/runs/rules-run/procedure-results")
    assert response.status_code == 200
    result = response.json()
    assert result["kind"] == "audit" and result["available"] is True
    assert result["audit"]["devices"][0]["confirmed_count"] == 0
    assert result["progress"] is None and result["procedure"]["version"] is None
    outside = root / "outside.jsonl"
    outside.write_text('{"private":"outside"}\n')
    (directory / "tool_calls.jsonl").symlink_to(outside)
    assert client.get("/api/runs/rules-run/procedure-results").status_code == 404


def test_rules_progress_remains_available_during_deployment_before_topology(procedure_api):
    client, root = procedure_api
    directory = root / "rules-run"
    directory.mkdir()
    (directory / "run_meta.json").write_text(json.dumps({"runner_kind": "rules", "status": "running"}))
    progress = RulesProcedureProgress(directory, auto_teardown=True)
    progress.observe({"type": "deploy_start"})
    response = client.get("/api/runs/rules-run/procedure-results")
    assert response.status_code == 200
    result = response.json()
    assert result["available"] is True and result["audit"]["available"] is False
    assert _step(result["progress"], "deployment")["status"] == "running"


def test_simple_worker_records_live_directory_before_terminal(monkeypatch, tmp_path):
    from src.agent import run_modes
    events = []

    class Runner:
        run_dir = tmp_path

        def run(self, stream_callback, **kwargs):
            stream_callback({"type": "runner_started", "runner_kind": "scripted", "run_dir": str(tmp_path)})
            assert pipeline._state["run_dir"] == str(tmp_path)
            stream_callback({"type": "runner_done", "status": "completed", "run_dir": str(tmp_path)})
            return {"scripted": "completed"}

    monkeypatch.setattr(run_modes, "make_runner", lambda *args, **kwargs: Runner())
    monkeypatch.setattr(pipeline, "_state", {"running": True, "stop_event": threading.Event(),
        "run_dir": None, "queue": SimpleNamespace(put_nowait=events.append),
        "loop": SimpleNamespace(call_soon_threadsafe=lambda callback, event: callback(event))})
    pipeline._simple_runner_thread(pipeline.StartRequest(runner_kind="scripted", script_id="smoke-v1"))
    assert pipeline._state["run_dir"] == str(tmp_path)
    assert events[-1]["type"] == "__done__"


def test_rules_worker_emits_durable_progress_before_terminal_without_a_model(monkeypatch, tmp_path):
    from src.agent import provider, run_modes
    events = []

    class Runner:
        run_dir = tmp_path
        scenario_id = "1"

        def run(self, stream_callback, **kwargs):
            for event in [
                {"type": "deploy_start"}, {"type": "deploy_done", "success": True},
                {"type": "inject_done", "success": True}, {"type": "verify_done", "success": True},
                {"type": "phase_start", "phase": 3}, {"type": "phase_done", "phase": 3, "status": "completed"},
                {"type": "phase_done", "phase": 4, "status": "executed_with_worker_errors"},
                {"type": "teardown_start"}, {"type": "teardown_done", "success": True},
                {"type": "pipeline_done", "status": "partial", "total_cost_usd": 0},
            ]:
                stream_callback(event)
            # The wrapper writes its summary after the internal terminal event.
            (tmp_path / "run_summary.md").write_text("# Rules observations\n")
            return {"vuln_analysis": "completed", "exploitation": "executed_with_worker_errors"}

    monkeypatch.setattr(run_modes, "make_runner", lambda *args, **kwargs: Runner())
    monkeypatch.setattr(provider, "LLMProvider", lambda **kwargs: pytest.fail("Unexpected model construction"))
    monkeypatch.setattr(pipeline, "_state", {"running": True, "stop_event": threading.Event(),
        "cost": 0, "run_dir": None, "queue": SimpleNamespace(put_nowait=events.append),
        "loop": SimpleNamespace(call_soon_threadsafe=lambda callback, event: callback(event))})
    pipeline._pipeline_thread(pipeline.StartRequest(runner_kind="rules", scenario_id="1"))
    snapshots = [event["progress"] for event in events if event["type"] == "procedure_progress"]
    assert snapshots
    assert _step(snapshots[-2], "results")["status"] == "running"
    assert _step(snapshots[-1], "results")["status"] == "completed"
    assert _step(snapshots[-1], "verification")["status"] == "partial"
    assert snapshots[-1]["controls_complete"] is False
    assert json.loads((tmp_path / "procedure_progress.json").read_text()) == snapshots[-1]
    assert [event["type"] for event in events][-2:] == ["pipeline_done", "__done__"]
