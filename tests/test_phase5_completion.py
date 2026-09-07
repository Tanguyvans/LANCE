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
    assert results["intrusion"] == "failed:validation"
    pipeline._run_compact_intrusion_fallback.assert_not_called()
    pipeline._run_compact_intrusion_post_access.assert_not_called()
