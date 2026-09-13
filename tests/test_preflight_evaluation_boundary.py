"""Preparation failures are environment failures, not agent false negatives."""
import json
from unittest.mock import Mock

import pytest

from src.agent.core.lifecycle import ScenarioLifecycle
from src.benchmark.evaluator import evaluate
from tests.test_evaluation_funnel import finding, write_run, confirmation, proof


@pytest.mark.parametrize("status,phase,scenario,contract,scoreable", [
    ("passed", "verify", "demo", "preflight-v1", True),
    ("failed", "inject", "demo", "preflight-v1", False),
    ("failed", "verify", "demo", "preflight-v1", False),
    ("pending", "verify", "demo", "preflight-v1", False),
    ("passed", "deploy", "demo", "preflight-v1", False),
    ("passed", "verify", "other", "preflight-v1", False),
    ("passed", "verify", "demo", "unknown", False),
])
def test_preflight_gates_official_funnel_without_rewriting_reference(
    tmp_path, status, phase, scenario, contract, scoreable,
):
    a = finding("a", "192.0.2.1")
    run, gt = write_run(tmp_path, [a], [a], [confirmation(a)], records=[proof(a)])
    path = run / "run_meta.json"
    metadata = json.loads(path.read_text())
    metadata["environment_validation"] = {
        "status": status, "phase": phase, "scenario_id": scenario, "contract": contract,
    }
    path.write_text(json.dumps(metadata))
    originals = {p: p.read_bytes() for p in [gt, *run.iterdir()] if p.is_file()}
    result = evaluate(run, gt, policy="strict-v3")
    assert result.environment_validation["scoreable"] is scoreable
    if scoreable:
        assert result.funnel["stages"]["confirmed"]["true_positives"] == 1
        assert result.scenario_score_pct is not None
    else:
        assert result.scenario_score_pct is None
        assert "Préparation" in result.score_unavailable_reason
        for stage in result.funnel["stages"].values():
            assert stage["available"] is False
            assert stage["false_negatives"] is None
        assert result.funnel["diagnostics"]["claims"]["available"] is False
    assert all(p.read_bytes() == contents for p, contents in originals.items())


@pytest.mark.parametrize("outcomes,expected_phase", [
    ([False], "deploy"), ([True, False], "inject"), ([True, True, False], "verify"),
    ([True, True, True], "verify"),
])
def test_real_deploy_lifecycle_records_preflight_and_stops_on_failure(outcomes, expected_phase):
    lifecycle = ScenarioLifecycle()
    lifecycle.scenario_id = None  # no exported scenario/inventory access in test
    lifecycle._update_run_meta = Mock()
    lifecycle._teardown_all_running_scenarios = Mock()
    lifecycle._run_playbook = Mock(side_effect=outcomes)
    lifecycle._run_teardown = Mock()
    success = lifecycle._run_scenario_deploy()
    assert success is all(outcomes)
    state = lifecycle._update_run_meta.call_args.args[0]["environment_validation"]
    assert state["status"] == ("passed" if success else "failed")
    assert state["phase"] == expected_phase
    assert state["all_ground_truth_properties_verified"] is False
    assert lifecycle._run_playbook.call_count == len(outcomes)
    assert lifecycle._run_teardown.call_count == (0 if success else 1)
