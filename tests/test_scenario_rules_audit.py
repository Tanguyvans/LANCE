"""Rules scenario audits: real orchestration, simulated deployment and probes."""
import json
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from src.agent.core import runtime
from src.agent.core.graph_context import current_graph_context
from src.agent.pipeline import Pipeline
from src.agent.rules_audit import device_results
from src.agent.run_modes import make_runner
from src.api.routes import pipeline as route


@pytest.mark.parametrize("fields", [
    {}, {"scenario_id": "1", "model": "unused"}, {"scenario_id": "1", "provider": "local"},
    {"scenario_id": "1", "target_network": "192.0.2.0/24"},
    {"scenario_id": "1", "blind": True}, {"scenario_id": "1", "deploy_only": True},
    {"scenario_id": "1", "phases": [1, 2, 3, 4]}, {"scenario_id": "1", "execution_profile": "compact"},
    {"scenario_id": "1", "max_cost_usd": 1}, {"scenario_id": "1", "max_duration_s": float("inf")},
])
def test_rules_request_rejects_mixed_or_missing_execution_contract(fields):
    with pytest.raises(ValidationError):
        route.StartRequest(runner_kind="rules", **fields)


@pytest.mark.parametrize("selection", [{"scenario_id": "1"}, {"architecture": "edge", "posture": "hardened"}])
def test_rules_request_needs_no_model_and_captures_limits(selection):
    request = route.StartRequest(runner_kind="rules", **selection)
    assert request.model is request.provider is None
    assert request.execution_profile == "full"
    assert request.max_tool_calls == 200 and request.max_duration_s == 600


@pytest.mark.parametrize("positive, interruption", [(False, None), (True, None), (False, "deploy"), (False, "stop"), (False, "budget")])
def test_rules_scenario_deploys_then_audits_with_zero_llm_calls(tmp_path, monkeypatch, positive, interruption):
    calls, deployments = [], []
    stop = threading.Event()

    def forbidden(*args, **kwargs):
        pytest.fail("Offline rules test accessed a model, pricing or private scenario narrative")

    def topology(scenario):
        current_graph_context().scenario_topology = {
            "nodes": [{"id": "web", "ip": "192.0.2.10", "type": "compute", "role": "web",
                       "services": [{"name": "http", "port": 80}]}],
            "edges": [], "subnets": ["192.0.2.0/24"],
        }
        current_graph_context().scenario_topology["node_index"] = {
            node["id"]: node for node in current_graph_context().scenario_topology["nodes"]
        }
        return {"device_count": 1, "link_count": 0, "cve_count": 0, "top_risk": None}

    def probe(**kwargs):
        assert deployments == ["deploy"], "No probe may precede scenario preparation"
        calls.append(kwargs)
        if positive and kwargs.get("url", "").endswith("/backup/"):
            body = '<h1>Index of /backup/</h1><a href="credentials.txt">credentials.txt</a>'
            stdout = f"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n{body}"
        elif positive and kwargs.get("url", "").endswith("credentials.txt"):
            stdout = "HTTP/1.1 200 OK\r\n\r\nusername=fixture\npassword=fixture-only"
        else:
            stdout = "HTTP/1.1 403 Forbidden\r\n\r\nAccess denied"
        return json.dumps({"stdout": stdout, "return_code": 0})

    tools = [{"name": name, "description": "Offline HTTP probe", "input_schema": {"type": "object", "properties": {}}, "function": probe}
             for name in ("curl_headers", "http_get")]
    def deploy(run, callback):
        run._scenario_owned = True
        deployments.append("deploy")
        if interruption == "stop":
            stop.set()
        return interruption != "deploy"
    monkeypatch.setattr(runtime, "RECON_TOOLS", tools)
    monkeypatch.setattr(runtime, "TOOL_GROUPS", {**runtime.TOOL_GROUPS, "recon": tools})
    monkeypatch.setattr(runtime, "filter_unavailable_tools", lambda value: (value, []))
    monkeypatch.setattr("src.agent.tools.tool_loader.filter_unavailable_tools", lambda value: (value, []))
    monkeypatch.setattr("src.agent.tools.graph_tools.load_scenario_topology", topology)
    monkeypatch.setattr(runtime, "init_weighted_graph", lambda: None)
    monkeypatch.setattr(Pipeline, "_run_scenario_deploy", deploy)
    monkeypatch.setattr(Pipeline, "_run_teardown", lambda *args: deployments.append("cleanup") or True)
    monkeypatch.setattr(Pipeline, "_persist_run", lambda *args: None)
    monkeypatch.setattr(Pipeline, "_load_scenario_context", forbidden)
    monkeypatch.setattr("src.agent.cost_tracker.get_dynamic_pricing", forbidden)
    monkeypatch.setattr(runtime, "LLMProvider", forbidden)
    runner = make_runner("rules", scenario_id="1", output_dir=tmp_path,
                         max_tool_calls=1 if interruption == "budget" else 200)
    events = []
    if interruption == "budget":
        from src.agent.cost_tracker import BudgetExceeded
        with pytest.raises(BudgetExceeded):
            runner.run(stream_callback=events.append, stop_event=stop)
        result = {}
    else:
        result = runner.run(stream_callback=events.append, stop_event=stop)
    if interruption:
        assert deployments == ["deploy", "cleanup"]
        assert len(calls) == (1 if interruption == "budget" else 0)
        metadata = json.loads((runner.run_dir / "run_meta.json").read_text())
        assert metadata["status"] == {"deploy": "failed", "stop": "stopped", "budget": "budget_exceeded"}[interruption]
        assert device_results(runner.run_dir)["devices"][0]["analysis_status"] == "incomplete"
        assert runner.terminal_event["status"] == metadata["status"]
        return
    assert set(result) == {"vuln_analysis", "exploitation"}
    assert all(value == "completed" for value in result.values()), result
    assert deployments == ["deploy", "cleanup"]
    assert calls
    meta = json.loads((runner.run_dir / "run_meta.json").read_text())
    assert meta["runner_kind"] == meta["decision_policy"] == "rules"
    assert meta["provider"] is meta["model"] is None
    assert meta["effective_phases"] == [3, 4] and meta["oracle_access"] is False
    summary = json.loads((runner.run_dir / "cost_summary.json").read_text())
    assert summary["total_turns"] == summary["total_input_tokens"] == summary["total_cost_usd"] == 0
    view = device_results(runner.run_dir)
    assert view["available"] and view["devices"][0]["analysis_status"] == "completed"
    assert bool(view["devices"][0]["findings"]) == positive
    assert view["devices"][0]["confirmed_count"] > 0 if positive else view["devices"][0]["confirmed_count"] == 0
    assert (runner.run_dir / "run_summary.md").is_file()


def test_confirmation_label_without_tool_evidence_stays_indeterminate(tmp_path):
    files = {
        "audit_topology.json": {"nodes": [{"id": "web", "ip": "192.0.2.10"}], "edges": []},
        "03_vuln_analysis.json": {"vulnerabilities": [{"id": "V1", "device_id": "web", "device_ip": "192.0.2.10", "type": "directory_listing", "service": "http", "port": 80}]},
        "04_exploitation.json": {"tests": [{"vuln_id": "V1", "status": "CONFIRMED"}]},
    }
    for name, data in files.items():
        (tmp_path / name).write_text(json.dumps(data))
    view = device_results(tmp_path)
    assert view["devices"][0]["confirmed_count"] == 0
    assert view["devices"][0]["verification_status"] == "incomplete"


def test_api_exposes_rules_results_and_excludes_them_from_benchmark(tmp_path, monkeypatch):
    from src.api.main import app
    from src.api.routes import runs
    directory = tmp_path / "rules-run"
    directory.mkdir()
    (directory / "run_meta.json").write_text(json.dumps({"runner_kind": "rules", "status": "completed"}))
    (directory / "audit_topology.json").write_text(json.dumps({"nodes": [{"id": "web", "ip": "192.0.2.10"}], "edges": []}))
    monkeypatch.setattr(runs, "OUTPUT_DIR", tmp_path)
    with TestClient(app) as client:
        assert client.get("/api/runs/rules-run").json()["runner_kind"] == "rules"
        result = client.get("/api/runs/rules-run/audit-results")
        assert result.status_code == 200
        assert result.json()["devices"][0]["analysis_status"] == "pending"
    assert runs._benchmark_candidate(directory) is None


def test_api_worker_selects_rules_without_constructing_provider(tmp_path, monkeypatch):
    from src.agent import run_modes, provider
    captured, events = {}, []

    class Loop:
        def call_soon_threadsafe(self, callback, event):
            callback(event)

    class Journal:
        def put_nowait(self, event):
            events.append(event)

    class Runner:
        run_dir = tmp_path
        scenario_id = "1"
        terminal_event = None

        def run(self, **kwargs):
            kwargs["stream_callback"]({"type": "phase_done", "phase": 4, "status": "completed"})
            kwargs["stream_callback"]({"type": "pipeline_done", "status": "completed", "total_cost_usd": 0})
            return {"vuln_analysis": "completed", "exploitation": "completed"}

    def create(kind, **kwargs):
        captured.update(kind=kind, **kwargs)
        return Runner()

    monkeypatch.setattr(run_modes, "make_runner", create)
    monkeypatch.setattr(provider, "LLMProvider", lambda **kwargs: pytest.fail("Rules worker created a model"))
    monkeypatch.setattr(route, "_state", {"running": True, "teardown_running": False, "lab_waiting": False, "stopping": False,
                                         "cost": 0, "queue": Journal(), "loop": Loop(), "recent_events": [],
                                         "stop_event": threading.Event(), "phases_done": []})
    route._pipeline_thread(route.StartRequest(runner_kind="rules", scenario_id="1"))
    assert captured["kind"] == "rules" and captured["provider"] is None
    assert captured["max_tool_calls"] == 200 and captured["max_duration_s"] == 600
    phase = next(event for event in events if event["type"] == "phase_done")
    assert phase["runner_kind"] == "rules" and phase["run_dir"] == str(tmp_path)
    evaluation = next(event for event in events if event["type"] == "evaluation_done")
    terminal = next(event for event in events if event["type"] == "pipeline_done")
    assert evaluation["status"] == terminal["evaluation_status"] == "not_applicable"
    assert terminal["status"] == "completed" and terminal["evaluation_reason"] == evaluation["reason"]
    assert "evaluation_error" not in terminal
    assert events[-1]["type"] == "__done__"


def test_rules_scenario_remains_blocked_for_sealed_evaluation(monkeypatch):
    from src.api.main import app
    from types import SimpleNamespace
    monkeypatch.setattr(route, "threading", SimpleNamespace(Thread=lambda **kwargs: pytest.fail("Sealed request started a worker"), Event=threading.Event))
    monkeypatch.setattr("src.benchmark.catalog.load_catalog", lambda: SimpleNamespace(
        get=lambda identifier: SimpleNamespace(id=identifier, sealed=True)))
    monkeypatch.setattr(route, "_state", dict(route._state, running=False, teardown_running=False))
    with TestClient(app) as client:
        result = client.post("/api/pipeline/start", json={"runner_kind": "rules", "scenario_id": "20"})
    assert result.status_code == 503


def test_derived_summary_failure_preserves_the_audit_exception(monkeypatch, tmp_path):
    from src.agent.run_modes import LanceRunner

    class FailedPipeline:
        run_dir = tmp_path

        def run(self, **kwargs):
            raise RuntimeError("primary audit failure")

    def fail_summary(*args):
        raise OSError("summary write failure")

    monkeypatch.setattr("src.agent.rules_audit.write_summary", fail_summary)
    with pytest.raises(RuntimeError, match="primary audit failure"):
        LanceRunner(FailedPipeline(), "rules").run()
