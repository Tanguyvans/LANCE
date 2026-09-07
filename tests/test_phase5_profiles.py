"""Profile modules are testable without constructing a Pipeline."""
from unittest.mock import Mock

import pytest

from src.agent.phases.intrusion.compact import finalize_incomplete, recover_completion
from src.agent.phases.intrusion.evidence import finalize_synthesis


@pytest.mark.parametrize("observations,max_rounds,executed,expected_calls,ready", [
    ([(True, {})], 2, 1, 0, True),
    ([(False, {"missing": 2}), (False, {"missing": 2})], 2, 1, 1, False),
    ([(False, {"missing": 2}), (False, {"missing": 1})], 2, 0, 1, False),
    ([(False, {"missing": 3}), (False, {"missing": 2}), (False, {"missing": 1})], 2, 1, 2, False),
    ([(False, {"missing": 1}), (True, {})], 2, 1, 1, True),
    ([(False, {"missing": 1})], 0, 1, 0, False),
])
def test_recovery_is_bounded_and_only_completes_with_coverage(
    observations, max_rounds, executed, expected_calls, ready
):
    calls = Mock()
    calls.coverage.side_effect = observations
    calls.recover.return_value = executed
    calls.complete.return_value = True
    calls.commit.return_value = True
    committed, coverage_ok, details = recover_completion(
        coverage=calls.coverage, recover=calls.recover, post_access=calls.post_access,
        complete=calls.complete, commit=calls.commit, max_rounds=max_rounds,
    )
    assert committed is ready and coverage_ok is ready
    assert details == observations[-1][1]
    assert calls.recover.call_count == expected_calls
    calls.post_access.assert_called_once()
    assert calls.complete.call_count == int(ready)
    assert calls.commit.call_count == int(ready)
    if ready:
        names = [call[0] for call in calls.mock_calls]
        assert names.index("post_access") < names.index("complete") < names.index("commit")


@pytest.mark.parametrize("terminal,committed", [(False, True), (True, False)])
def test_recovery_requires_both_terminal_completion_and_commit(terminal, committed):
    commit = Mock(return_value=committed)
    result = recover_completion(
        coverage=lambda: (True, {}), recover=Mock(), post_access=Mock(),
        complete=lambda: terminal, commit=commit, max_rounds=2,
    )
    assert result == (False, True, {})
    assert commit.call_count == int(terminal)


def test_same_evidence_keeps_profile_policies_distinct():
    full = {"summary": {"devices_attempted": 1}}
    compact = {"summary": {"devices_attempted": 1}}
    assert finalize_synthesis(full, "failed:validation") == "failed:validation"
    assert "status" not in full
    assert finalize_incomplete(compact, coverage_ok=True, coverage={}) == "failed:phase5_completion_missing"
    assert compact["status"] == "incomplete"


def test_profiles_share_no_observable_actions_boundary():
    full = {"summary": {"devices_attempted": 0}}
    compact = {"summary": {"devices_attempted": 0}}
    assert finalize_synthesis(full, "completed") == finalize_incomplete(compact, coverage_ok=True, coverage={})
    assert full == compact
    assert full["status"] == "blocked"
