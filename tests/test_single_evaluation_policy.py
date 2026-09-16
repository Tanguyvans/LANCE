"""All entry points use the current contract; archives are never relabelled."""
import json
from dataclasses import asdict

import pytest

from src.benchmark.evaluator import (
    EVALUATION_POLICIES, STRICT_V3, EvaluationPolicy, evaluate, resolve_policy,
)
from src.learning.error_mining import DEFAULT_POLICY, mine_runs
from tests.test_evaluation_funnel import confirmation, finding, proof, write_run


def test_only_current_policy_is_supported():
    assert EVALUATION_POLICIES == {STRICT_V3.name: STRICT_V3}
    assert DEFAULT_POLICY == STRICT_V3.name
    assert resolve_policy(STRICT_V3) is STRICT_V3


@pytest.mark.parametrize("policy", [
    "legacy-v1", "strict-v2", "strict-v99",
    EvaluationPolicy("strict-v3", min_match_credit=0),
])
def test_retired_or_custom_policies_fail_before_io(tmp_path, policy):
    with pytest.raises(ValueError):
        evaluate(tmp_path / "missing-run", tmp_path / "missing-gt", policy=policy)
    output = tmp_path / "corpus"
    with pytest.raises(ValueError):
        mine_runs(tmp_path / "missing-run", output, policy=policy)
    assert not output.exists()


@pytest.mark.parametrize("status", ["CONFIRMED", "FAILED", "ERROR", "SKIPPED"])
def test_default_and_explicit_current_policy_are_identical(tmp_path, status):
    f = finding("F1", "192.0.2.1")
    run, gt = write_run(tmp_path, [f], [f], [confirmation(f, status=status)],
                        truth=[f], records=[proof(f)])
    implicit = evaluate(run, gt)
    assert asdict(implicit) == asdict(evaluate(run, gt, policy=STRICT_V3))
    stage = implicit.funnel["stages"]["confirmed"]
    assert stage["true_positives"] == (1 if status == "CONFIRMED" else 0)
    assert implicit.funnel["stages"]["candidates"]["true_positives"] == 1
    if status != "CONFIRMED":
        from src.agent.judge import _findings_payload, _load_llm_findings

        predictions = _load_llm_findings(run)
        assert len(predictions) == 1
        assert predictions[0]["status"] == "DETECTED"
        assert _findings_payload(predictions)[0]["evidence_level"] <= 1


def test_learning_cli_rejects_retired_policy(tmp_path):
    from src.learning.error_mining import main

    with pytest.raises(SystemExit) as exc:
        main(["mine", "--output", str(tmp_path / "corpus"), "--policy", "strict-v2"])
    assert exc.value.code == 2
    assert not (tmp_path / "corpus").exists()


def test_archived_run_remains_readable_but_not_currently_scoreable(tmp_path):
    f = finding("F1", "192.0.2.1")
    run, gt = write_run(tmp_path, [f], [f], [confirmation(f)], truth=[f],
                        records=[proof(f)], metadata={
                            "metric_contract_version": "strict-v3.9",
                            "evidence_contract_version": "evidence-v9",
                        })
    before = (run / "run_meta.json").read_bytes()
    result = evaluate(run, gt)
    assert not result.evidence_contract_compatible
    assert result.scenario_score_pct is None
    assert not result.funnel["stages"]["confirmed"]["available"]
    assert (run / "run_meta.json").read_bytes() == before


@pytest.mark.parametrize("metadata,reason", [
    ({"metric_contract_version": "strict-v3.9", "evidence_contract_version": "evidence-v9"}, "contract"),
    ({"environment_validation": {"contract": "preflight-v1", "status": "failed",
                                  "phase": "verify", "scenario_id": "1"}}, "laboratory"),
    ({"environment_validation": "malformed"}, "laboratory"),
])
def test_learning_skips_incompatible_or_invalid_runs(tmp_path, metadata, reason):
    from tests.test_learning_error_mining import _write_gt, _write_run

    runs = tmp_path / "runs"
    run = _write_run(runs)
    path = run / "run_meta.json"
    path.write_text(json.dumps({**json.loads(path.read_text()), **metadata}))
    gt_dir = tmp_path / "gt"
    _write_gt(gt_dir)
    manifest = mine_runs(runs, tmp_path / "dataset", ground_truth_dir=gt_dir)
    assert manifest["candidate_count"] == 0
    assert manifest["processed_runs"] == []
    assert reason in manifest["skipped_runs"][0]["reason"].lower()
