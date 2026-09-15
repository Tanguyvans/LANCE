"""Phase 3 execution status must survive deterministic aggregation."""

from unittest.mock import patch

from src.agent.core import runtime
from src.agent.pipeline import Pipeline
from src.agent.registry import AgentConfig
from src.agent.results import run_status


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

    def run_phase3(*_args):
        pipeline._phase3_execution_status = phase3_status

    monkeypatch.setattr(pipeline, "_run_phase3", run_phase3)
    monkeypatch.setattr(pipeline, "_aggregate_device_vulns", lambda *_args: None)
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
