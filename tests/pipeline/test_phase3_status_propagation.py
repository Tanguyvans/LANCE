"""Phase 3 execution status must survive deterministic aggregation."""

from unittest.mock import patch

from src.agent.core import runtime
from src.agent.pipeline import Pipeline
from src.agent.registry import AgentConfig
from src.agent.results import run_status
from src.agent.phases.contracts import PhaseStatus
from src.agent.phases.analysis import run as analysis
from src.agent.phases.analysis.context import (
    AnalysisExecutionResult,
    DeviceAnalysisResult,
    DeviceResult,
    ScanResult,
)


CONFIG = AgentConfig(
    name="vuln_analysis",
    phase=3,
    prompt_template="vuln_analysis",
    deliverable_file="03_vuln_analysis.json",
    tools=[],
    validator="phase3_status_test",
    has_device_agents=True,
    deterministic_aggregation=True,
)


def _run_aggregated_case(monkeypatch, output_dir, mock_provider, phase3_status, valid=True):
    pipeline = Pipeline(provider=mock_provider, execution_profile="full")
    events = []

    monkeypatch.setattr(runtime, "get_attack_surface", lambda: "[]")
    monkeypatch.setattr(analysis, "scan_phase", lambda _context: ScanResult([], {}))
    monkeypatch.setattr(analysis, "analyze_devices", lambda *_args: DeviceAnalysisResult(
        (DeviceResult("device", "worker failed"),) if phase3_status else (),
    ))
    monkeypatch.setattr(analysis, "aggregate", lambda *_args: None)
    monkeypatch.setattr(runtime, "filter_profile_tools", lambda _profile, _phase, tools: tools)
    monkeypatch.setattr(runtime, "load_prompt", lambda *_args: "prompt")
    monkeypatch.setitem(
        runtime.VALIDATORS,
        "phase3_status_test",
        lambda _filename, **kwargs: (valid, "invalid aggregation" if not valid else "valid"),
    )

    status = pipeline._run_agent(CONFIG, events.append)
    phase_done = next(event for event in events if event.get("type") == "phase_done")
    return status, phase_done["status"]


def test_valid_aggregation_keeps_complete_status(monkeypatch, output_dir, mock_provider):
    status, event_status = _run_aggregated_case(
        monkeypatch, output_dir, mock_provider, None, valid=True
    )

    assert status == event_status == "completed"
    assert run_status({"vuln_analysis": status}) == "completed"


def test_device_worker_errors_are_partial_after_valid_aggregation(
    monkeypatch, output_dir, mock_provider,
):
    for phase3_status in ("executed_with_worker_errors",):
        status, event_status = _run_aggregated_case(
            monkeypatch, output_dir, mock_provider, phase3_status, valid=True
        )

        assert status == event_status == "executed_with_worker_errors"
        assert run_status({"vuln_analysis": status}) == "partial"


def test_invalid_aggregation_remains_failure_even_after_phase3_errors(
    monkeypatch, output_dir, mock_provider,
):
    status, event_status = _run_aggregated_case(
        monkeypatch,
        output_dir,
        mock_provider,
        "executed_with_worker_errors",
        valid=False,
    )

    assert status == event_status == "failed:invalid aggregation"
    assert run_status({"vuln_analysis": status}) == "failed"


def test_surface_error_without_devices_is_not_completed(
    output_dir, mock_provider,
):
    pipeline = Pipeline(provider=mock_provider, execution_profile="full")
    config = CONFIG
    with patch.object(runtime, "get_attack_surface", side_effect=RuntimeError("surface unavailable")), \
         patch.object(runtime, "run_scanner", return_value={}):
        pipeline._run_phase3(config)

    assert pipeline._phase3_execution_status == "executed_with_worker_errors"
    assert (pipeline.run_dir / "03_phase3_status.json").exists()


def test_scanner_error_without_devices_is_not_completed(output_dir, mock_provider):
    pipeline = Pipeline(provider=mock_provider, execution_profile="full")
    with patch.object(runtime, "get_attack_surface", return_value="[]"), \
         patch.object(
             runtime,
             "run_scanner",
             return_value={"scanner": {"error": "scanner unavailable"}},
         ):
        pipeline._run_phase3(CONFIG)

    assert pipeline._phase3_execution_status == "executed_with_worker_errors"


def test_scanner_errors_with_all_devices_analyzed_stay_completed():
    # S12 run 2026-10-07_122920: one mqtt_listen probe failed (x2) yet all
    # 35 devices were analyzed. A recovered scanner transient must not
    # degrade the phase once every device has its analysis.
    execution = AnalysisExecutionResult(
        scan=ScanResult(
            devices=[{"id": "s12-mqtt2"}],
            observations={},
            scanner_errors=("s12-mqtt2: mqtt_listen returned an error (×2)",),
        ),
        analysis=DeviceAnalysisResult(
            devices=(DeviceResult(device_id="s12-mqtt2"),),
            worker_count=1,
        ),
    )
    assert execution.status is not PhaseStatus.WORKER_ERRORS
    assert execution.status.value == "completed"


def test_scanner_errors_with_failed_device_stay_worker_errors():
    execution = AnalysisExecutionResult(
        scan=ScanResult(
            devices=[{"id": "d1"}],
            observations={},
            scanner_errors=("d1: probe failed",),
        ),
        analysis=DeviceAnalysisResult(
            devices=(DeviceResult(device_id="d1", error="worker failed"),),
            worker_count=1,
        ),
    )
    assert execution.status is PhaseStatus.WORKER_ERRORS
