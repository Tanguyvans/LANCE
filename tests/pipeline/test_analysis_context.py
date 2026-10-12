"""Phase 3 boundaries: isolated run inputs, terminal errors and worker outcomes."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import fields, replace
import json
from threading import Barrier, Event
from unittest.mock import Mock

import pytest

from src.agent.core import runtime
from src.agent.core.executor import EvidenceWriteError, RunStopped
from src.agent.cost_tracker import BudgetExceeded, CostTracker
from src.agent.execution_profiles import resolve_execution_profile
from src.agent.phases.analysis import devices, run as analysis
from src.agent.phases.analysis.context import AnalysisContext, AnalysisServices, ScanResult
from src.agent.phases.contracts import PhaseStatus
from src.agent.pipeline import Pipeline
from src.agent.registry import AGENTS
from src.agent.tools import graph_tools


@pytest.fixture(autouse=True)
def aggregation(monkeypatch):
    # These tests exercise phase outcomes, not graph initialization or NVD.
    monkeypatch.setattr(runtime, "get_attack_surface", lambda: "[]")
    lab_loader = Mock(
        side_effect=AssertionError("phase boundary test initialized the lab context"),
    )
    monkeypatch.setattr(graph_tools, "load_lab_context", lab_loader)
    operation = Mock(wraps=analysis.aggregate)
    monkeypatch.setattr(analysis, "aggregate", operation)
    yield operation
    lab_loader.assert_not_called()


def context_for(path, **overrides):
    path.mkdir(exist_ok=True)
    operations = {field.name: Mock() for field in fields(AnalysisServices)}
    operations.update(
        wrap_tool=Mock(side_effect=lambda tool, **kwargs: tool),
        apply_tool_policy=Mock(side_effect=lambda tools, phase: tools),
        validate=Mock(return_value=(True, "valid")),
    )
    return AnalysisContext(
        run_dir=path, config=AGENTS["vuln_analysis"], provider=Mock(),
        tracker=CostTracker(), profile=resolve_execution_profile("full"),
        services=AnalysisServices(**operations), variables={}, **overrides,
    )


def test_context_captures_effective_provider_profile_and_variables(output_dir, mock_provider):
    pipeline = Pipeline(provider=mock_provider, execution_profile="full")
    effective = Mock(provider="ollama-umons", model="selected-phase-model")
    pipeline.provider = effective
    pipeline.benchmark_split = "dev"
    pipeline.context["selected"] = "phase input"
    context = analysis.build_context(pipeline, AGENTS["vuln_analysis"])
    pipeline.provider = mock_provider
    pipeline.benchmark_split = "test"
    pipeline.execution_profile = resolve_execution_profile("compact")
    pipeline.context["selected"] = "later change"

    assert context.provider is effective
    assert context.benchmark_split == "dev"
    assert context.profile.name == "full"
    assert context.variables["selected"] == "phase input"
    assert devices.analysis_worker_count(context, 4) == 1
    scan = {"scan_results": {"http": [{"result": "A" * 12000}]}}
    assert devices.project_scan(context.profile, scan, "same") is scan


def test_dry_run_skips_active_discovery_scanner_model_and_aggregation(tmp_path, monkeypatch, aggregation):
    events = []
    context = context_for(tmp_path, dry_run=True, target_network="192.0.2.0/24", emit=events.append)
    monkeypatch.setattr(runtime, "get_attack_surface", lambda: "[]")
    scanner = Mock(side_effect=AssertionError("scanner must not run"))
    monkeypatch.setattr(runtime, "run_scanner", scanner)

    result = analysis.execute(context)

    assert result.status is PhaseStatus.SKIPPED
    assert [event["type"] for event in events] == ["phase_start", "phase_done"]
    assert events[-1]["status"] == "skipped"
    assert json.loads((tmp_path / "03_phase3_status.json").read_text())["status"] == "skipped"
    context.services.discover_surface.assert_not_called()
    aggregation.assert_not_called()
    context.provider.chat_with_tools.assert_not_called()
    scanner.assert_not_called()


def test_aggregation_only_configuration_does_not_scan_or_analyze(tmp_path, monkeypatch, aggregation):
    context = context_for(tmp_path)
    context = replace(context, config=replace(context.config, has_device_agents=False))
    scan = Mock(side_effect=AssertionError("scan must not run"))
    analyze = Mock(side_effect=AssertionError("devices must not run"))
    monkeypatch.setattr(analysis, "scan_phase", scan)
    monkeypatch.setattr(analysis, "analyze_devices", analyze)

    result = analysis.execute(context)

    assert result.status is PhaseStatus.COMPLETED
    aggregation.assert_called_once()
    scan.assert_not_called()
    analyze.assert_not_called()


@pytest.mark.parametrize("error_type", [BudgetExceeded, EvidenceWriteError, RunStopped])
@pytest.mark.parametrize("stage", ["scanner", "device"])
def test_terminal_error_blocks_aggregation(tmp_path, monkeypatch, error_type, stage, aggregation):
    events = []
    context = context_for(tmp_path, emit=events.append)
    monkeypatch.setattr(runtime, "get_attack_surface", lambda: '[{"id":"same"}]')
    scanner = Mock(side_effect=error_type("terminal")) if stage == "scanner" else Mock(
        return_value={"same": {"findings": [], "scan_results": {}}},
    )
    monkeypatch.setattr(runtime, "run_scanner", scanner)
    monkeypatch.setattr(devices, "prepare_analysis", lambda _: object())
    def fail_device(*_args):
        context.tracker.start_phase("interrupted_device")
        context.tracker.record_turn(10, 5)
        raise error_type("terminal")

    device = Mock(side_effect=fail_device)
    monkeypatch.setattr(devices, "analyze_device", device)

    with pytest.raises(error_type, match="terminal"):
        analysis.execute(context)
    aggregation.assert_not_called()
    context.services.persist_findings.assert_not_called()
    if stage == "scanner":
        device.assert_not_called()
    assert context.tracker._active == {}
    assert not any(event["type"] == "phase_done" for event in events)


def test_reverse_worker_completion_preserves_exact_partial_accounting(tmp_path, monkeypatch):
    context = context_for(tmp_path)
    scan = ScanResult([{"id": str(index)} for index in range(3)], {})
    monkeypatch.setattr(analysis, "scan_phase", lambda _: scan)
    monkeypatch.setattr(devices, "prepare_analysis", lambda _: object())
    monkeypatch.setattr(devices.time, "sleep", lambda _: None)
    barrier, second_done = Barrier(3), Event()
    order = []

    def analyze(_context, _setup, _scan, device):
        barrier.wait(timeout=5)
        if device["id"] == "0":
            assert second_done.wait(timeout=5)
        order.append(device["id"])
        if device["id"] == "1":
            raise RuntimeError("invalid model output")
        if device["id"] == "2":
            second_done.set()

    monkeypatch.setattr(devices, "analyze_device", analyze)
    result = analysis.execute(context)
    status = json.loads((tmp_path / "03_phase3_status.json").read_text())

    assert order.index("2") < order.index("0")
    assert result.status is PhaseStatus.WORKER_ERRORS
    assert status["devices_total"] == 3
    assert status["devices_analyzed"] == 2
    assert status["devices_failed"] == [{"device_id": "1", "error": "invalid model output"}]
    context.services.persist_findings.assert_called_once_with(scan.devices[1], scan.observations)


def test_two_contexts_with_same_device_id_keep_artifacts_callbacks_and_usage_isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "get_attack_surface", lambda: "[]")
    contexts = []
    events = [[], []]
    for index in range(2):
        context = context_for(tmp_path / str(index), emit=events[index].append)
        # Usage accumulated before the phase must not enter this phase result.
        context.tracker.start_phase("previous")
        context.tracker.record_turn(100, 50)
        context.tracker.end_phase()
        context = replace(context, tokens_before=context.tracker.total_tokens())

        (context.run_dir / "03_device_same.json").write_text(json.dumps({
            "vulnerabilities": [{
                "device_id": "same", "device_ip": f"192.0.2.{10 + index}",
                "type": "data_exposure", "severity": "MEDIUM", "service": "http",
                "port": 80, "protocol": "tcp", "endpoint": "/config",
                "details": f"Configuration may be public on run {index}",
            }],
        }))
        contexts.append(context)
    monkeypatch.setattr(analysis, "scan_phase", lambda _: ScanResult([{"id": "same"}], {}))
    monkeypatch.setattr(devices, "prepare_analysis", lambda _: object())

    def analyze(context, _setup, _scan, _device):
        context.tracker.start_phase("analyze_same")
        context.tracker.record_turn(7 + int(context.run_dir.name), 3)
        context.tracker.end_phase()

    monkeypatch.setattr(devices, "analyze_device", analyze)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(analysis.execute, contexts))
    for index, (context, result) in enumerate(zip(contexts, results)):
        assert result.status is PhaseStatus.COMPLETED
        assert result.consumption.input_tokens == 7 + index
        assert result.consumption.output_tokens == 3
        assert result.consumption.duration_s >= 0
        canonical = json.loads((context.run_dir / context.config.deliverable_file).read_text())
        assert canonical["vulnerabilities"][0]["device_ip"] == f"192.0.2.{10 + index}"
        assert [event["type"] for event in events[index]] == ["phase_start", "phase_done"]
        assert all((context.run_dir / name).is_file() for name in result.artifacts)


def test_rules_without_provider_counts_validation_and_closes_tracking(tmp_path, monkeypatch, aggregation):
    events = []
    context = replace(context_for(tmp_path, emit=events.append), decision_policy="rules", provider=None)
    monkeypatch.setattr(runtime, "get_attack_surface", lambda: '[{"id":"same"}]')
    scanner = Mock(return_value={"same": {"scan_results": {}, "findings": []}})
    monkeypatch.setattr(runtime, "run_scanner", scanner)

    result = analysis.execute(context)

    assert result.status is PhaseStatus.COMPLETED
    scanner.assert_called_once()
    aggregation.assert_called_once()
    assert [event["type"] for event in events] == ["phase_start", "phase_done"]
    assert [usage.agent_name for usage in context.tracker.phases] == ["rules_analysis", "rules_validate_3"]
    assert context.tracker.phases[-1].validation_successes == 1
    assert context.tracker._active == {}


def test_consumption_excludes_prior_cost_and_tokens(tmp_path, monkeypatch):
    import src.agent.cost_tracker as tracking
    monkeypatch.setattr(tracking, "_resolve_pricing", lambda *args: (
        {"input": 1.0, "output": 2.0}, "local-test", False,
    ))
    events = []
    context = context_for(tmp_path, emit=events.append)
    context.tracker.model = "test-model"
    context.tracker.start_phase("previous")
    context.tracker.record_turn(9000, 4000)
    context.tracker.end_phase()
    context = replace(context, tokens_before=context.tracker.total_tokens(),
                      cost_before=context.tracker.total_cost(),
                      turns_before=context.tracker.summary()["total_turns"])
    monkeypatch.setattr(analysis, "scan_phase", lambda _: ScanResult([{"id": "same"}], {}))
    monkeypatch.setattr(devices, "prepare_analysis", lambda _: object())

    def analyze(context, _setup, _scan, _device):
        context.tracker.start_phase("analyze_same")
        context.tracker.record_turn(1000, 500)
        context.tracker.end_phase()

    monkeypatch.setattr(devices, "analyze_device", analyze)
    result = analysis.execute(context)
    assert result.consumption.input_tokens == 1000
    assert result.consumption.output_tokens == 500
    assert result.consumption.cost_usd == pytest.approx(0.002)
    assert result.consumption.turns == 1
    assert events[-1]["cost_usd"] == pytest.approx(0.002)
    assert events[-1]["turns"] == 1
    assert context.tracker._active == {}
