"""Phase 5 reconciliation contracts, with all execution mocked."""
import json
from unittest.mock import Mock

import pytest

from src.agent.pipeline import Pipeline
from src.agent.registry import AGENTS


@pytest.fixture
def pipeline(tmp_path):
    pipeline = Pipeline.__new__(Pipeline)
    pipeline.run_dir = tmp_path
    pipeline._uses_compact_local_moe = Mock(return_value=True)
    pipeline._compact_intrusion_completion_succeeded = Mock(return_value=False)
    pipeline._compact_intrusion_coverage = Mock(return_value=(True, {}))
    pipeline._run_compact_intrusion_fallback = Mock(return_value=0)
    pipeline._run_compact_intrusion_post_access = Mock(return_value=0)
    pipeline._invoke_compact_intrusion_completion = Mock(return_value=False)
    pipeline._write_compact_intrusion_deliverable = Mock(return_value=True)
    pipeline._synthesize_intrusion_from_tools = Mock(return_value={
        "summary": {"devices_attempted": 1, "devices_compromised": 0, "credentials_harvested": 0},
    })
    return pipeline


@pytest.mark.parametrize("coverage,actions,expected", [
    (True, 1, "failed:phase5_completion_missing"),
    (False, 1, "failed:phase5_contract_incomplete"),
    (True, 0, "blocked:phase5_no_observable_actions"),
    (False, 0, "blocked:phase5_no_observable_actions"),
])
def test_incomplete_reconciliation_keeps_status_and_single_event(pipeline, coverage, actions, expected):
    pipeline._compact_intrusion_coverage.return_value = (coverage, {"missing_targets": [] if coverage else ["test-device"]})
    pipeline._synthesize_intrusion_from_tools.return_value["summary"]["devices_attempted"] = actions
    results, events = {}, []
    pipeline._ensure_intrusion_deliverable(AGENTS["intrusion"], results, events.append)
    data = json.loads((pipeline.run_dir / "05_intrusion.json").read_text())
    assert results == {"intrusion": expected}
    assert data["status"] == ("blocked" if not actions else "incomplete")
    assert data["blocked_reason"] == data["summary"]["_note"]
    assert len(events) == 1
    assert events[0]["status"] == expected
    assert pipeline._run_compact_intrusion_fallback.call_count == int(not coverage)


@pytest.mark.parametrize("already_completed,already_reported", [(True, True), (True, False), (False, False)])
def test_success_emits_no_duplicate_and_preserves_post_access(pipeline, already_completed, already_reported):
    pipeline._compact_intrusion_completion_succeeded.return_value = already_completed
    pipeline._invoke_compact_intrusion_completion.return_value = True
    results = {"intrusion": "completed" if already_reported else "failed:empty"}
    events = []
    pipeline._ensure_intrusion_deliverable(AGENTS["intrusion"], results, events.append)
    assert results == {"intrusion": "completed"}
    assert len(events) == int(not already_reported)
    if events:
        assert events[0] == {
            "type": "phase_done", "phase": 5, "name": "intrusion",
            "status": "completed", "deliverable": "05_intrusion.json",
            "cost_usd": 0, "turns": 0,
        }
    pipeline._run_compact_intrusion_post_access.assert_called_once()
    pipeline._write_compact_intrusion_deliverable.assert_called_once()
    pipeline._synthesize_intrusion_from_tools.assert_not_called()


def test_failed_commit_is_not_promoted_to_completed(pipeline):
    pipeline._invoke_compact_intrusion_completion.return_value = True
    pipeline._write_compact_intrusion_deliverable.return_value = False
    results = {}
    pipeline._ensure_intrusion_deliverable(AGENTS["intrusion"], results)
    assert results["intrusion"] == "failed:phase5_completion_missing"


def test_full_profile_synthesis_preserves_failed_phase_status(pipeline):
    pipeline._uses_compact_local_moe.return_value = False
    results = {"intrusion": "failed:validation"}
    pipeline._ensure_intrusion_deliverable(AGENTS["intrusion"], results)
    assert results["intrusion"] == "failed:phase5_completion_invalid"
    assert json.loads((pipeline.run_dir / "05_intrusion.json").read_text())["status"] == "incomplete"
    pipeline._run_compact_intrusion_fallback.assert_not_called()
    pipeline._run_compact_intrusion_post_access.assert_not_called()


def _observed_ledger(attempted=1):
    return {"summary": {
        "devices_attempted": attempted, "devices_compromised": 0,
        "credentials_harvested": 0,
    }}


def test_finalize_missing_without_submission():
    from src.agent.phases.intrusion.evidence import finalize_synthesis
    assert finalize_synthesis(
        _observed_ledger(), "failed:Deliverable '05_intrusion.json' not found"
    ) == "failed:phase5_completion_missing"


def test_finalize_invalid_after_rejected_submission():
    from src.agent.phases.intrusion.evidence import finalize_synthesis
    assert finalize_synthesis(
        _observed_ledger(), "failed:Deliverable '05_intrusion.json' not found",
        submitted=True,
    ) == "failed:phase5_completion_invalid"


def test_finalize_interruptions_unchanged_even_when_submitted():
    from src.agent.phases.intrusion.evidence import finalize_synthesis
    assert finalize_synthesis(_observed_ledger(), "stopped", submitted=True) == "stopped"
    assert finalize_synthesis(
        _observed_ledger(), "budget_exceeded:phase5", submitted=True
    ) == "budget_exceeded:phase5"


def test_finalize_no_actions_stays_blocked_even_when_submitted():
    from src.agent.phases.intrusion.evidence import finalize_synthesis
    assert finalize_synthesis(
        _observed_ledger(attempted=0), "failed:Deliverable '05_intrusion.json' not found",
        submitted=True,
    ) == "blocked:phase5_no_observable_actions"


@pytest.mark.parametrize("phase,agent,expected", [(5, "intrusion", True), (3, "analysis", False)])
def test_submission_archive_is_scoped_to_intrusion(pipeline, phase, agent, expected):
    (pipeline.run_dir / "deliverable_attempts.jsonl").write_text(json.dumps({
        "filename": "05_intrusion.json", "phase": phase, "agent": agent, "valid": False,
    }) + "\n")
    assert pipeline._phase5_finish_submitted("05_intrusion.json") is expected
