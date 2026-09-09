"""Lifecycle tests never deploy a scenario or invoke an LLM."""
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock
from threading import Event

import pytest

from src.agent.core import runtime
from src.agent.pipeline import Pipeline
from src.agent.cost_tracker import BudgetExceeded, CostTracker, PhaseUsage
from src.agent.results import run_status


@pytest.mark.parametrize("results,termination,expected", [
    ({"recon": "completed:synthesized"}, None, "completed"),
    ({"exploitation": "executed_with_worker_errors"}, None, "partial"),
    ({"recon": "failed:missing"}, None, "failed"),
    ({"report": "skipped:prerequisites"}, None, "blocked"),
    ({"exploitation": "skipped:conditional"}, None, "skipped"),
    ({"recon": "completed"}, "stopped", "stopped"),
    ({"recon": "completed"}, "budget_exceeded", "budget_exceeded"),
    ({"intrusion": "blocked:no_evidence"}, None, "blocked"),
    ({}, None, "skipped"),
    ({"recon": "error"}, None, "failed"),
    ({"recon": "unexpected"}, None, "failed"),
    ({"recon": "stopped", "report": "skipped:prerequisites"}, None, "stopped"),
])
def test_terminal_status(results, termination, expected):
    assert run_status(results, termination) == expected


@pytest.fixture
def pipeline(tmp_path):
    instance = Pipeline.__new__(Pipeline)
    instance.run_dir = tmp_path
    instance.auto_teardown = True
    instance.dry_run = False
    instance._run_teardown = Mock(return_value=True)
    instance._update_run_meta = Mock()
    instance._persist_run = Mock()
    instance.tracker = MagicMock(spec=CostTracker)
    instance.tracker.total_cost.return_value = 0.125
    instance.tracker.total_tokens.return_value = (0, 0)
    instance.tracker.summary.return_value = {"phases": []}
    instance.tracker.to_json.return_value = json.dumps({"total_cost_usd": 0.125})
    instance.tracker.budget_exhausted = False
    return instance


def test_cleanup_runs_on_phase_exception_and_preserves_exception(pipeline):
    def execute(*_):
        pipeline._scenario_owned = True
        pipeline._active_phase = "recon"
        raise RuntimeError("phase failed")
    pipeline._execute_run = execute
    with pytest.raises(RuntimeError, match="phase failed"):
        pipeline.run()
    pipeline._run_teardown.assert_called_once()
    assert pipeline._update_run_meta.call_args.args[0]["status"] == "failed"
    assert pipeline._update_run_meta.call_args.args[0]["results"] == {"recon": "failed:exception"}
    pipeline._persist_run.assert_called_once_with("failed")


@pytest.mark.parametrize("owned,auto,dry", [(False, True, False), (True, False, False), (True, True, True)])
def test_cleanup_respects_ownership_and_options(pipeline, owned, auto, dry):
    pipeline.auto_teardown = auto
    pipeline.dry_run = dry
    def execute(*_):
        pipeline._scenario_owned = owned
        return {}
    pipeline._execute_run = execute
    assert pipeline.run() == {}
    pipeline._run_teardown.assert_not_called()


def test_cleanup_error_does_not_mask_phase_error(pipeline):
    pipeline._run_teardown.side_effect = ValueError("cleanup failed")
    def execute(*_):
        pipeline._scenario_owned = True
        raise RuntimeError("original")
    pipeline._execute_run = execute
    with pytest.raises(RuntimeError, match="original"):
        pipeline.run()
    assert pipeline._update_run_meta.call_args.args[0]["cleanup_status"] == "failed"


def test_done_is_emitted_after_cleanup_with_terminal_state(pipeline):
    events = []
    def execute(callback, _):
        pipeline._scenario_owned = True
        pipeline._run_results["recon"] = "completed"
        assert not events
        return pipeline._run_results
    pipeline._execute_run = execute
    pipeline._run_teardown.side_effect = lambda callback: callback({"type": "teardown_done"}) or True
    pipeline.run(events.append)
    pipeline._run_teardown.assert_called_once()
    assert events[-1]["status"] == "completed"
    assert events[-1]["cleanup_status"] == "completed"
    assert [event["type"] for event in events] == ["teardown_done", "pipeline_done"]
    assert events[-1]["total_cost_usd"] == 0.125


def test_cleanup_failure_is_not_reported_as_success(pipeline):
    pipeline._run_teardown.return_value = False
    def execute(*_):
        pipeline._scenario_owned = True
        pipeline._run_results["recon"] = "completed"
        return pipeline._run_results
    pipeline._execute_run = execute
    pipeline.run()
    assert pipeline._update_run_meta.call_args.args[0]["status"] == "partial"


def test_stop_during_last_phase_is_preserved(pipeline):
    stop = Event()
    def execute(*_):
        pipeline._run_results["report"] = "completed"
        stop.set()
        return pipeline._run_results
    pipeline._execute_run = execute
    pipeline.run(stop_event=stop)
    assert pipeline._update_run_meta.call_args.args[0]["status"] == "stopped"


def test_deploy_failure_emits_one_terminal_event(pipeline):
    def execute(*_):
        pipeline._termination = "failed"
        return {}
    pipeline._execute_run = execute
    events = []
    assert pipeline.run(events.append) == {}
    assert len(events) == 1
    assert events[0]["type"] == "pipeline_done"
    assert events[0]["status"] == "failed"


def test_exception_is_not_reported_as_a_completed_run(pipeline):
    pipeline._execute_run = Mock(side_effect=RuntimeError("phase failed"))
    events = []
    with pytest.raises(RuntimeError, match="phase failed"):
        pipeline.run(events.append)
    assert not events
    pipeline._persist_run.assert_called_once_with("failed")


@pytest.fixture
def real_tracker_pipeline(tmp_path):
    instance = Pipeline.__new__(Pipeline)
    instance.run_dir = tmp_path
    instance.auto_teardown = True
    instance.dry_run = False
    instance.tracker = CostTracker(
        model="offline",
        provider="codex",
        phases=[PhaseUsage(
            agent_name="recon",
            input_tokens=125_000,
            input_price_per_million=1,
            output_price_per_million=0,
        )],
    )
    instance._run_teardown = Mock(return_value=True)
    instance._persist_run = Mock()
    return instance


def _set_lifecycle_execution(pipeline, *, error=None, phase_status="completed", stop=None):
    def execute(*_):
        pipeline._scenario_owned = True
        pipeline._active_phase = "recon"
        pipeline._run_results["recon"] = phase_status
        if stop is not None:
            stop.set()
        if error is not None:
            raise error
        return pipeline._run_results

    pipeline._execute_run = execute


@pytest.mark.parametrize("failure", ["finalize", "serialize", "write"])
@pytest.mark.parametrize("cause", ["success", "exception"])
def test_usage_finalization_and_export_are_isolated(real_tracker_pipeline, monkeypatch, failure, cause):
    pipeline = real_tracker_pipeline
    original = RuntimeError("original phase error") if cause == "exception" else None
    _set_lifecycle_execution(pipeline, error=original)
    if failure == "finalize":
        monkeypatch.setattr(pipeline.tracker, "finalize", Mock(side_effect=ValueError("finalize failed")))
    elif failure == "serialize":
        monkeypatch.setattr(pipeline.tracker, "to_json", Mock(side_effect=TypeError("serialization failed")))
    else:
        write_text = Path.write_text

        def fail_cost(path, *args, **kwargs):
            if path.name == "cost_summary.json":
                raise OSError("disk failure")
            return write_text(path, *args, **kwargs)

        monkeypatch.setattr(Path, "write_text", fail_cost)

    events = []
    if original is None:
        pipeline.run(events.append)
    else:
        with pytest.raises(RuntimeError) as caught:
            pipeline.run(events.append)
        assert caught.value is original

    pipeline._run_teardown.assert_called_once()
    expected = "partial" if original is None else "failed"
    meta = json.loads((pipeline.run_dir / "run_meta.json").read_text())
    assert meta["status"] == expected
    assert meta["usage_status"] == "incomplete"
    assert any(error.startswith(failure) for error in meta["usage_errors"])
    pipeline._persist_run.assert_called_once_with(expected)
    if original is None:
        assert events[-1]["status"] == expected
        assert events[-1]["total_cost_usd"] == 0.125
    else:
        assert events == []


def test_keyboard_interrupt_during_usage_preserves_stop_and_cleanup(real_tracker_pipeline, monkeypatch):
    pipeline = real_tracker_pipeline
    _set_lifecycle_execution(pipeline)
    interrupt = KeyboardInterrupt("interrupted during finalize")
    monkeypatch.setattr(pipeline.tracker, "finalize", Mock(side_effect=interrupt))

    with pytest.raises(KeyboardInterrupt) as caught:
        pipeline.run()

    assert caught.value is interrupt
    pipeline._run_teardown.assert_called_once()
    meta = json.loads((pipeline.run_dir / "run_meta.json").read_text())
    assert meta["status"] == "stopped"


@pytest.mark.parametrize("phase_status,signal_stop,expected", [
    ("completed", False, "budget_exceeded"),
    ("failed:validation", False, "failed"),
    ("stopped", False, "stopped"),
    ("completed", True, "stopped"),
])
def test_budget_flag_does_not_replace_phase_or_stop_cause(
    real_tracker_pipeline, phase_status, signal_stop, expected,
):
    pipeline = real_tracker_pipeline
    pipeline.tracker.budget_exhausted = True
    stop = Event()
    _set_lifecycle_execution(pipeline, phase_status=phase_status, stop=stop if signal_stop else None)
    events = []
    pipeline.run(events.append, stop_event=stop)

    assert events[-1]["status"] == expected
    assert json.loads((pipeline.run_dir / "run_meta.json").read_text())["status"] == expected


def test_budget_exception_preserves_budget_terminal_cause(real_tracker_pipeline):
    pipeline = real_tracker_pipeline
    _set_lifecycle_execution(pipeline, error=BudgetExceeded("limit"))

    with pytest.raises(BudgetExceeded):
        pipeline.run()

    assert json.loads((pipeline.run_dir / "run_meta.json").read_text())["status"] == "budget_exceeded"
    pipeline._run_teardown.assert_called_once()


def test_stop_during_cleanup_overrides_budget_flag(real_tracker_pipeline):
    pipeline = real_tracker_pipeline
    pipeline.tracker.budget_exhausted = True
    _set_lifecycle_execution(pipeline)
    interrupt = KeyboardInterrupt("stop during cleanup")
    pipeline._run_teardown.side_effect = interrupt

    with pytest.raises(KeyboardInterrupt) as caught:
        pipeline.run()

    assert caught.value is interrupt
    meta = json.loads((pipeline.run_dir / "run_meta.json").read_text())
    assert meta["status"] == "stopped"
    assert meta["cleanup_status"] == "failed"


@pytest.mark.parametrize("budget_flag", [False, True])
@pytest.mark.parametrize("initial_error", [False, True])
def test_stop_received_during_cleanup_has_terminal_priority(
    real_tracker_pipeline, budget_flag, initial_error,
):
    pipeline = real_tracker_pipeline
    pipeline.tracker.budget_exhausted = budget_flag
    original = RuntimeError("phase failed") if initial_error else None
    _set_lifecycle_execution(pipeline, error=original)
    stop = Event()

    def teardown(_callback):
        stop.set()
        return True

    pipeline._run_teardown.side_effect = teardown
    if initial_error:
        with pytest.raises(RuntimeError) as caught:
            pipeline.run(stop_event=stop)
        assert caught.value is original
        expected = "failed"
    else:
        pipeline.run(stop_event=stop)
        expected = "stopped"

    meta = json.loads((pipeline.run_dir / "run_meta.json").read_text())
    assert meta["status"] == expected
    assert meta["cleanup_status"] == "completed"


def test_metadata_failure_does_not_hide_original_with_real_usage(real_tracker_pipeline, monkeypatch):
    pipeline = real_tracker_pipeline
    original = RuntimeError("phase failed")
    _set_lifecycle_execution(pipeline, error=original)
    monkeypatch.setattr(pipeline, "_update_run_meta", Mock(side_effect=ValueError("metadata failed")))

    with pytest.raises(RuntimeError) as caught:
        pipeline.run()

    assert caught.value is original
    pipeline._run_teardown.assert_called_once()
    pipeline._persist_run.assert_called_once_with("failed")


def test_unavailable_cost_is_not_reported_as_zero(pipeline):
    pipeline.tracker.total_cost.side_effect = TypeError("cost unavailable")
    pipeline._execute_run = Mock(return_value={})
    events = []

    pipeline.run(events.append)

    assert events[-1]["total_cost_usd"] is None


def _configured_budget_pipeline(tmp_path, monkeypatch):
    import src.agent.pipeline as pipeline_module
    import src.agent.tools.graph_tools as graph_tools

    monkeypatch.setattr(pipeline_module, "OUTPUT_DIR", tmp_path)
    monkeypatch.setattr(runtime, "load_lab_context", lambda: {
        "device_count": 0, "link_count": 0, "cve_count": 0, "top_risk": "none",
    })
    monkeypatch.setattr(runtime, "init_weighted_graph", lambda: None)
    monkeypatch.setattr(graph_tools, "_scenario_topology", None)
    monkeypatch.setattr(graph_tools, "_backend", None)
    pipeline = Pipeline(
        provider=SimpleNamespace(model="offline", provider="codex"),
        phases=[1, 2], max_cost_usd=1.0,
    )
    pipeline._check_prerequisites = lambda *_: True
    pipeline._check_conditional = lambda *_: True
    pipeline._build_graph_evidence_projection = lambda: None
    pipeline._build_recon_evidence_projection = lambda: None
    pipeline._persist_run = Mock()
    pipeline._run_teardown = Mock(return_value=True)
    return pipeline, pipeline_module


def test_budget_measurement_failure_prevents_next_phase(tmp_path, monkeypatch):
    """A configured budget cannot become best-effort after cost inspection fails."""
    pipeline, pipeline_module = _configured_budget_pipeline(tmp_path, monkeypatch)
    original = RuntimeError("cannot check configured budget")
    pipeline.tracker.total_cost = Mock(side_effect=original)
    phases = []

    def run_phase(instance, config, callback):
        instance._scenario_owned = True
        phases.append(config.phase)
        return "completed"

    monkeypatch.setattr(pipeline_module, "run_phase", run_phase)
    with pytest.raises(RuntimeError) as caught:
        pipeline.run()
    assert caught.value is original
    assert phases == [1]
    pipeline._run_teardown.assert_called_once()
    assert json.loads((pipeline.run_dir / "run_meta.json").read_text())["status"] == "failed"


def test_failed_phase_below_budget_does_not_change_phase_flow(tmp_path, monkeypatch):
    pipeline, pipeline_module = _configured_budget_pipeline(tmp_path, monkeypatch)
    pipeline.tracker.total_cost = Mock(side_effect=[0.5, 0.5])
    phases = []

    def run_phase(instance, config, callback):
        instance._scenario_owned = True
        phases.append(config.phase)
        return "failed:validation" if config.phase == 1 else "completed"

    monkeypatch.setattr(pipeline_module, "run_phase", run_phase)
    result = pipeline.run()

    assert phases == [1, 2]
    assert result == {"graph_analysis": "failed:validation", "recon": "completed"}
    assert json.loads((pipeline.run_dir / "run_meta.json").read_text())["status"] == "failed"
