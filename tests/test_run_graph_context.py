"""Run and worker graph isolation without network, model or laboratory calls."""
from concurrent.futures import ThreadPoolExecutor
import json
from threading import Barrier
from types import SimpleNamespace

import pytest

from src.agent.core.graph_context import (
    GraphContext, bind_graph_context, current_graph_context,
)
from src.agent.core.run_context import RunContext
from src.agent.phases.context import PhaseContext, PhaseServices, phase_context
from src.agent.phases.registry import run_phase
from src.agent.pipeline import Pipeline
from src.agent.registry import AGENTS
from src.agent.tools import graph_tools


@pytest.fixture
def runs(tmp_path, monkeypatch):
    monkeypatch.setattr("src.agent.cost_tracker._resolve_pricing", lambda *_a, **_k: (
        {"input": 0, "output": 0}, "offline", True,
    ))
    monkeypatch.setattr("src.agent.core.runtime.filter_unavailable_tools", lambda tools: (tools, {}))
    result = []
    for index in (1, 2):
        run = Pipeline(
            provider=SimpleNamespace(provider="offline", model="offline"),
            execution_profile="full", manage_scenario=False, output_dir=tmp_path,
        )
        with bind_graph_context(run.run_context.graph):
            graph_tools.load_discovery_context(f"192.0.{index}.0/24")
            graph_tools.update_discovery_hosts([
                {"id": "same-id", "ip": f"192.0.{index}.1", "role": "router", "services": []},
                {"id": "neighbor", "ip": f"192.0.{index}.2", "role": "sensor", "services": []},
            ])
            graph_tools.init_weighted_graph()
        result.append(run)
    return result


def test_constructor_and_graph_reset_do_not_replace_another_runs_state(runs):
    first, second = runs
    assert first.run_context.graph is not second.run_context.graph
    assert first.run_context.graph.weighted_graph is not second.run_context.graph.weighted_graph
    first_graph = first.run_context.graph.weighted_graph
    with bind_graph_context(second.run_context.graph):
        graph_tools.load_discovery_context("198.51.100.0/24")
    assert first.run_context.graph.weighted_graph is first_graph
    assert first.run_context.graph.discovery_mode["target_network"] == "192.0.1.0/24"
    assert second.run_context.graph.weighted_graph is None


def test_tool_graph_binding_survives_another_run_and_concurrent_workers(runs):
    barrier = Barrier(2)
    tools = [run._wrap_tool(next(t for t in graph_tools.GRAPH_TOOLS if t["name"] == "get_attack_surface"),
                            phase=1, agent="graph_analysis") for run in runs]

    def observe(index):
        barrier.wait(timeout=5)
        return json.loads(tools[index]["function"]())

    with ThreadPoolExecutor(max_workers=2) as workers:
        observations = list(workers.map(observe, range(2)))
    for index, (run, surface) in enumerate(zip(runs, observations), 1):
        assert surface[0]["ip"] == f"192.0.{index}.1"
        assert {node["ip"] for node in surface} == {f"192.0.{index}.1", f"192.0.{index}.2"}
        records = [json.loads(line) for line in (run.run_dir / "tool_calls.jsonl").read_text().splitlines()]
        assert len(records) == 1 and json.loads(records[0]["result"]) == surface


def test_weighted_mutation_and_disbalance_belong_to_their_run(runs):
    first, second = runs
    with bind_graph_context(first.run_context.graph):
        report = graph_tools.trigger_disbalance_on_exploit("same-id", "EXPLOITED")
        assert json.loads(graph_tools.get_graph_disbalance()) == report
    assert first.run_context.graph.last_disbalance_report is report
    assert second.run_context.graph.last_disbalance_report is None


def test_nested_binding_restores_previous_graph_after_failure():
    previous = current_graph_context()
    first, second = GraphContext(), GraphContext()
    with bind_graph_context(first):
        with pytest.raises(RuntimeError):
            with bind_graph_context(second):
                assert current_graph_context() is second
                raise RuntimeError("synthetic failure")
        assert current_graph_context() is first
    assert current_graph_context() is previous


@pytest.mark.parametrize("phase", [1, 2, 4, 5, 6])
@pytest.mark.parametrize("profile", ["full", "compact"])
def test_phase_entry_can_execute_with_explicit_services_without_pipeline(tmp_path, phase, profile):
    graph = GraphContext(discovery_mode={"target_network": "192.0.2.0/24"})
    calls = []

    def execute(config, callback):
        assert current_graph_context() is graph
        calls.append((config.phase, callback))
        return "partial:unchanged"

    callback = lambda event: None
    config = next(config for config in AGENTS.values() if config.phase == phase)
    context = PhaseContext(
        run_context=RunContext(tmp_path, graph), config=config,
        execution_profile=SimpleNamespace(name=profile), provider=None, tracker=None,
        variables={}, stop_event=None, decision_policy="llm",
        services=PhaseServices(execute=execute, record_analysis_status=lambda status: None),
        emit=callback,
    )
    assert run_phase(context, config) == "partial:unchanged"
    assert calls == [(phase, callback)]
    assert not hasattr(context, "_run_agent")


def test_phase_variables_are_captured_and_service_graph_is_bound(runs):
    first, second = runs
    first.context = {"nested": {"value": "first"}}
    first._run_agent = lambda config, emit: json.loads(graph_tools.get_network_topology())["target_network"]
    context = phase_context(first, AGENTS["graph_analysis"])
    first.context["nested"]["value"] = "later"
    assert context.variables["nested"]["value"] == "first"
    with bind_graph_context(second.run_context.graph):
        assert context.services.execute(context.config, None) == "192.0.1.0/24"
        assert current_graph_context() is second.run_context.graph


@pytest.mark.parametrize("profile", ["full", "compact"])
def test_analysis_entry_consumes_explicit_analysis_context_and_preserves_status(tmp_path, monkeypatch, profile):
    from src.agent.phases.analysis import run as analysis
    from src.agent.phases.contracts import PhaseResult, PhaseStatus

    graph = GraphContext()
    captured = SimpleNamespace(graph=graph)
    recorded = []

    def execute(context):
        assert context is captured and current_graph_context() is graph
        return PhaseResult(PhaseStatus.WORKER_ERRORS)

    monkeypatch.setattr(analysis, "execute", execute)
    config = AGENTS["vuln_analysis"]
    context = PhaseContext(
        run_context=RunContext(tmp_path, graph), config=config,
        execution_profile=SimpleNamespace(name=profile), provider=None, tracker=None,
        variables={}, stop_event=None, decision_policy="llm",
        services=PhaseServices(execute=lambda *_: pytest.fail("generic agent must not run"),
                               record_analysis_status=recorded.append),
        analysis=captured,
    )
    assert run_phase(context, config) == "executed_with_worker_errors"
    assert recorded == [None, "executed_with_worker_errors"]


def test_parallel_device_prompts_read_their_own_graph_and_neighbors(runs):
    from src.agent.phases.analysis.context import ScanResult
    from src.agent.phases.analysis.devices import build_device_prompt
    from src.agent.phases.analysis.run import build_context

    barrier = Barrier(2)
    contexts = [build_context(run, AGENTS["vuln_analysis"]) for run in runs]

    def prompt(index):
        context = contexts[index]
        device = context.graph.discovery_mode["discovered_hosts"][0]
        scan = ScanResult([device], {device["id"]: {"scan_results": {}, "findings": []}})
        barrier.wait(timeout=5)
        return build_device_prompt(context, scan, device).variables

    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(prompt, range(2)))
    for index, variables in enumerate(results, 1):
        assert f"192.0.{index}.2" in variables["network_neighbors_downstream"]
        assert f"192.0.{3-index}.2" not in variables["network_neighbors_downstream"]


def test_failed_analysis_context_capture_keeps_legacy_status_reset(runs, monkeypatch):
    from src.agent.phases.analysis import run as analysis

    first, _ = runs
    first._phase3_execution_status = "executed_with_worker_errors"

    def fail(*args):
        raise ValueError("synthetic capture failure")

    monkeypatch.setattr(analysis, "build_context", fail)
    previous = current_graph_context()
    with pytest.raises(ValueError, match="capture failure"):
        run_phase(first, AGENTS["vuln_analysis"])
    assert first._phase3_execution_status is None
    assert current_graph_context() is previous
