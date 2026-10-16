"""Execution overview fidelity, pagination and protected artifact reads."""
import json

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from src.agent.procedures import get_procedure
from src.api.routes import procedures, runs


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(runs, "OUTPUT_DIR", tmp_path)
    app = FastAPI()
    app.include_router(procedures.router, prefix="/api/procedures")
    return TestClient(app)


def _write(path, name, value):
    (path / name).write_text(json.dumps(value), encoding="utf-8")


def _run(root, identifier="2026-10-15_123829", *, script="service-inventory-v1"):
    path = root / identifier
    path.mkdir()
    network = None if script == "smoke-v1" else "192.0.2.0/28"
    descriptor = get_procedure(script)
    procedure = {key: descriptor[key] for key in ("id", "title", "version", "fingerprint")}
    metadata = {"runner_kind": "scripted", "script_id": script, "status": "completed",
        "target_network": network, "started_at": "2026-10-15T12:38:29+02:00",
        "finished_at": "2026-10-15T12:41:15+02:00", "total_tool_calls": 5}
    hosts = [] if network is None else [{"ip": "192.0.2.1", "status": "up", "services": [
        {"port": 22, "protocol": "tcp", "state": "open", "name": "ssh", "detail": "observed"}]}]
    results = {"schema_version": 1, "script_id": script, "status": "completed",
        "target_network": network, "procedure": procedure, "hosts": hosts,
        "counts": {"hosts": len(hosts), "services": len(hosts), "inspected_hosts": len(hosts)},
        "steps": [], "coverage": {"partial": False}, "errors": [], "evidence_refs": []}
    _write(path, "run_meta.json", metadata)
    _write(path, "procedure_results.json", results)
    _write(path, "cost_summary.json", {"total_tool_calls": 7, "total_tool_errors": 0,
        "total_duration_s": 999, "wall_clock_duration_s": 3})
    return path, metadata, results


def test_summary_uses_recorded_time_and_measurements_without_inventing_a_scenario(client, tmp_path):
    path, _, _ = _run(tmp_path)
    response = client.get(f"/api/procedures/runs/{path.name}")
    assert response.status_code == 200
    item = response.json()
    assert item["scenario"] is None and item["target"] == "192.0.2.0/28"
    assert item["duration_s"] == 166 and item["duration_scope"] == "total"
    assert item["tool_calls"] == 5 and item["tool_errors"] == 0
    assert item["observations"] == {"hosts": 1, "services": 1, "inspected_hosts": 1}
    assert item["coverage"] == "collected"
    assert item["evaluation"] == {"status": "not_evaluated", "reason": "scenario_not_recorded"}
    assert "f1" not in item


def test_page_filters_and_paginates_and_keeps_offline_diagnostics_opt_in(client, tmp_path):
    _run(tmp_path, "a")
    _run(tmp_path, "b", script="discovery-v1")
    _run(tmp_path, "c", script="smoke-v1")
    page = client.get("/api/procedures/runs?limit=1").json()
    assert page["total"] == 2 and [item["id"] for item in page["items"]] == ["b"]
    assert client.get("/api/procedures/runs?limit=1&offset=1").json()["items"][0]["id"] == "a"
    assert client.get("/api/procedures/runs?include_diagnostics=true").json()["total"] == 3
    filtered = client.get("/api/procedures/runs?procedure_id=discovery-v1&target=192.0.2.0/28").json()
    assert filtered["total"] == 1 and filtered["items"][0]["id"] == "b"
    assert client.get("/api/procedures/runs?target=S1").json()["total"] == 0


def test_unknown_or_unreadable_observations_do_not_become_zero_or_abort_the_page(client, tmp_path):
    path, _, _ = _run(tmp_path, "bad")
    (path / "procedure_results.json").write_text("broken json")
    _run(tmp_path, "good")
    items = {item["id"]: item for item in client.get("/api/procedures/runs").json()["items"]}
    assert items["bad"]["available"] is False and items["bad"]["observations"] is None
    assert items["bad"]["coverage"] == "unavailable" and items["good"]["available"] is True


def test_sealed_runs_and_symlinked_classification_are_never_exposed(client, tmp_path):
    path, metadata, _ = _run(tmp_path, "sealed")
    metadata["benchmark_split"] = "eval-sealed"
    _write(path, "run_meta.json", metadata)
    unsafe, _, _ = _run(tmp_path, "unsafe")
    (unsafe / "run_meta.json").unlink()
    (unsafe / "run_meta.json").symlink_to(path / "run_meta.json")
    (tmp_path / "linked").symlink_to(path, target_is_directory=True)
    assert client.get("/api/procedures/runs?include_diagnostics=true").json()["total"] == 0
    for identifier in ("sealed", "unsafe", "linked"):
        assert client.get(f"/api/procedures/runs/{identifier}").status_code == 404


def test_symlinked_observation_and_oversized_usage_stay_unavailable(client, tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_text('{"secret":"should never be returned"}')
    path, _, _ = _run(tmp_path)
    (path / "procedure_results.json").unlink()
    (path / "procedure_results.json").symlink_to(outside)
    response = client.get(f"/api/procedures/runs/{path.name}")
    assert response.json()["available"] is False and "secret" not in response.text
    (path / "cost_summary.json").write_bytes(b" " * (runs._PROCEDURE_JSON_LIMIT + 1))
    assert client.get(f"/api/procedures/runs/{path.name}").json()["available"] is False


def test_missing_and_nonfinite_metrics_are_unknown_and_agent_seconds_are_not_elapsed_time(client, tmp_path):
    path, metadata, _ = _run(tmp_path)
    metadata.update(started_at=None, finished_at=None, total_tool_calls=None)
    _write(path, "run_meta.json", metadata)
    _write(path, "cost_summary.json", {"total_duration_s": 999, "total_tool_errors": -1})
    item = client.get(f"/api/procedures/runs/{path.name}").json()
    assert item["duration_s"] is None and item["tool_calls"] is None and item["tool_errors"] is None
    _write(path, "cost_summary.json", {"wall_clock_duration_s": 3, "total_tool_calls": 0, "total_tool_errors": 0})
    item = client.get(f"/api/procedures/runs/{path.name}").json()
    assert item["duration_s"] == 3 and item["duration_scope"] == "tools"
    assert item["tool_calls"] == item["tool_errors"] == 0


def test_overview_preserves_archived_identity_and_exposes_partial_collection(client, tmp_path):
    path, _, results = _run(tmp_path)
    results["procedure"].update(title="Archived inventory", version="0.8.0")
    results.update(status="partial", coverage={"partial": True})
    _write(path, "procedure_results.json", results)
    item = client.get(f"/api/procedures/runs/{path.name}").json()
    assert item["procedure"]["title"] == "Archived inventory"
    assert item["procedure"]["version"] == "0.8.0" and item["coverage"] == "partial"


def test_rules_overview_records_scenario_without_promoting_declared_findings_to_scores(client, tmp_path, monkeypatch):
    from src.agent.rules_audit import device_results
    monkeypatch.setattr("src.agent.rules_audit.device_results", lambda _: pytest.fail("No ledger projection in list"))
    path = tmp_path / "rules"
    path.mkdir()
    descriptor = get_procedure("rules-audit-v1")
    _write(path, "run_meta.json", {"runner_kind": "rules", "status": "completed"})
    _write(path, "scenario_meta.json", {"scenario_id": "1", "split": "dev-public"})
    _write(path, "procedure_progress.json", {"schema_version": 1, "runner_kind": "rules", "status": "completed",
        "steps": [], "controls_complete": False,
        "procedure": {key: descriptor[key] for key in ("id", "title", "version", "fingerprint")}})
    _write(path, "04_exploitation.json", {"verdict": "CONFIRMED", "findings": [1, 2, 3]})
    item = client.get("/api/procedures/runs/rules").json()
    assert item["scenario"] == "S1" and item["observations"] is None
    assert item["coverage"] == "partial" and item["evaluation"]["status"] == "not_evaluated"


@pytest.mark.parametrize("query", ["offset=-1", "limit=0", "limit=51"])
def test_page_rejects_invalid_bounds(client, query):
    assert client.get(f"/api/procedures/runs?{query}").status_code == 422
