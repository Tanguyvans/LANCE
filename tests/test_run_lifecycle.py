"""Lifecycle tests never deploy a scenario or invoke an LLM."""
from unittest.mock import Mock
from threading import Event

import pytest

from src.agent.pipeline import Pipeline
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
    instance.tracker = Mock()
    instance.tracker.total_cost.return_value = 0.125
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
