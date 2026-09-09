"""Executable examples of the candidate -> filter -> confirmation contract."""
import json
from dataclasses import replace

import pytest
import yaml

from src.benchmark.evaluator import evaluate
from src.benchmark.aggregate import aggregate_evaluations
from src.benchmark.metric_contract import METRIC_CONTRACT_VERSION, EVIDENCE_CONTRACT_VERSION
from src.benchmark.funnel import unique_predictions


_COMPARABILITY_METADATA = {
    "provider": "fixture-provider", "model": "fixture-model",
    "execution_profile": "full", "execution_profile_policy": "full",
    "blind": False, "max_cost_usd": None, "max_tool_calls": None,
    "effective_phases": [1, 2, 3, 4, 5, 6], "phase_models": {},
    "execution_profile_config": {"schema_version": "2", "name": "full"},
    "prompt_manifest_sha256": "fixture-prompts", "tool_manifest_sha256": "fixture-tools",
    "scoring_policy": "strict-v3", "metric_contract_version": METRIC_CONTRACT_VERSION,
    "evidence_contract_version": EVIDENCE_CONTRACT_VERSION,
}


def finding(identifier, ip):
    return {
        "id": identifier, "device_ip": ip, "type": "data_exposure",
        "severity": "high", "service": "http", "port": 80,
        "protocol": "tcp", "endpoint": "/backup.sql", "cve_ids": [],
        "evidence": "Public backup may contain credentials",
    }


def write_run(tmp_path, raw, filtered, tests, *, truth=None, records=None, metadata=None):
    run = tmp_path / "run"
    run.mkdir()
    gt_findings = truth if truth is not None else [finding(str(n), f"192.0.2.{n}") for n in (1, 2, 3)]
    gt = tmp_path / "gt.yaml"
    gt.write_text(yaml.safe_dump({
        "scenario_id": "demo", "vulnerabilities": [{
            "id": f["id"], "title": "Exposed backup", "ip": f["device_ip"],
            "category": "data_exposure", "severity": "high",
            "accepted_types": ["data_exposure"], "services": ["http"],
            "ports": [80], "protocols": ["tcp"], "endpoints": ["/backup.sql"],
        } for f in gt_findings],
    }))
    (run / "run_meta.json").write_text(json.dumps(metadata or {
        "metric_contract_version": METRIC_CONTRACT_VERSION,
        "evidence_contract_version": EVIDENCE_CONTRACT_VERSION,
    }))
    (run / "03_vuln_analysis.json").write_text(json.dumps({"vulnerabilities": filtered}))
    if raw is not None:
        (run / "03_vuln_analysis_raw.json").write_text(json.dumps({
            "candidates": [{"candidate_id": f"C{i}", "candidate_finding": f, "decision": "selected"} for i, f in enumerate(raw)],
        }))
    if tests is not None:
        (run / "04_exploitation.json").write_text(json.dumps({"tests": tests}))
    if records is not None:
        (run / "tool_calls.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records))
    return run, gt


def confirmation(f, **kwargs):
    return {
        "vuln_id": f["id"], "status": "CONFIRMED", "evidence_level": 2,
        "tool_used": "http_get", "tools_used": ["http_get"],
        "evidence": "password=secret", "evidence_refs": [f"proof-{f['id']}"],
        **kwargs,
    }


def proof(f, **kwargs):
    return {
        "vuln_id": f["id"], "evidence_ref": f"proof-{f['id']}",
        "tool": "http_get", "args": {"url": f"http://{f['device_ip']}/backup.sql"},
        "result": {"return_code": 0, "status_code": 200, "body": "password=secret"},
        **kwargs,
    }


def test_three_stages_have_independent_predictions_and_losses(tmp_path):
    a, b, c, x, y = [finding(name, f"192.0.2.{ip}") for name, ip in zip("abcxy", (1, 2, 3, 9, 10))]
    run, gt = write_run(tmp_path, [a, dict(a, id="duplicate"), b, c, x, y], [a, b, x, y], [
        confirmation(a), {"vuln_id": "b", "status": "FAILED"},
        confirmation(x), {"vuln_id": "y", "status": "ERROR"},
    ], records=[proof(a), proof(x)])
    result = evaluate(run, gt, policy="strict-v3")
    stages = result.funnel["stages"]
    for name, expected in zip(("candidates", "filtered", "confirmed"), ((5, 3, 2, 0), (4, 2, 2, 1), (2, 1, 1, 2))):
        assert tuple(stages[name][k] for k in ("predictions", "true_positives", "false_positives", "false_negatives")) == expected
    assert stages["confirmed"]["precision"] == 0.5
    assert stages["confirmed"]["recall"] == 0.333
    assert result.verified_f1 == 0.4
    assert result.scenario_score_pct == 40.0
    d = result.funnel["diagnostics"]
    assert d["duplicate_candidates"] == 1
    assert d["true_candidates_lost_in_filter"] == 1
    assert d["true_candidates_not_confirmed"] == 1
    assert d["verification"] == {"confirmed": 2, "refuted": 0, "inconclusive": 1, "error": 1, "not_tested": 0}


@pytest.mark.parametrize("status", ["ERROR", "FAILED", "NOT_EXPLOITABLE", "SKIPPED", "TIMEOUT", "UNKNOWN"])
def test_unsuccessful_attempts_do_not_change_detection_metrics(tmp_path, status):
    a, x = finding("a", "192.0.2.1"), finding("x", "192.0.2.9")
    run, gt = write_run(tmp_path, [a, x], [a, x], [confirmation(a)], records=[proof(a)])
    before = evaluate(run, gt, policy="strict-v3")
    (run / "04_exploitation.json").write_text(json.dumps({"tests": [confirmation(a), {"vuln_id": "x", "status": status}]}))
    after = evaluate(run, gt, policy="strict-v3")
    assert before.funnel["stages"] == after.funnel["stages"]
    assert before.scenario_score_pct == after.scenario_score_pct == 50.0
    assert after.funnel["diagnostics"]["verification"]["refuted"] == 0


@pytest.mark.parametrize("result", [
    {"success": True},
    {"success": True, "status_code": 200, "body": "Welcome"},
    {"return_code": 0, "status_code": 403, "body": "password access denied"},
])
def test_reported_confirmation_requires_actual_support_not_success_flag(tmp_path, result):
    a = finding("a", "192.0.2.1")
    run, gt = write_run(tmp_path, [a], [a], [confirmation(a)], records=[proof(a, result=result)])
    evaluation = evaluate(run, gt, policy="strict-v3")
    stage = evaluation.funnel["stages"]["confirmed"]
    assert stage["predictions"] == stage["false_positives"] == stage["invalid_evidence"] == 1
    assert stage["ground_truth_matches"] == 1
    assert stage["true_positives"] == 0
    assert evaluation.scenario_score_pct == 0.0


def test_unverified_claim_is_not_a_report_prediction(tmp_path):
    a = finding("a", "192.0.2.1")
    run, gt = write_run(tmp_path, [a], [a], [confirmation(a, evidence_level=1)], records=[])
    result = evaluate(run, gt, policy="strict-v3")
    assert result.funnel["stages"]["confirmed"]["predictions"] == 0
    assert result.funnel["stages"]["confirmed"]["precision"] is None
    assert result.funnel["stages"]["confirmed"]["recall"] == 0.0
    assert result.scenario_score_pct == 0.0
    assert result.funnel["diagnostics"]["unsupported_declarations"] == 1


def test_missing_candidate_snapshot_never_copies_filtered_results(tmp_path):
    a = finding("a", "192.0.2.1")
    run, gt = write_run(tmp_path, None, [a], [confirmation(a)], records=[proof(a)])
    stages = evaluate(run, gt, policy="strict-v3").funnel["stages"]
    assert stages["candidates"]["available"] is False
    assert stages["candidates"]["predictions"] is None
    assert stages["filtered"]["true_positives"] == 1
    assert stages["confirmed"]["true_positives"] == 1


@pytest.mark.parametrize("missing", ["phase4", "provenance", "version"])
def test_missing_final_artifacts_or_old_contract_cannot_score(tmp_path, missing):
    a = finding("a", "192.0.2.1")
    run, gt = write_run(tmp_path, [a], [a], None if missing == "phase4" else [confirmation(a)], records=None if missing == "provenance" else [proof(a)])
    if missing == "version":
        (run / "run_meta.json").write_text(json.dumps({"metric_contract_version": "strict-v3.4", "evidence_contract_version": "evidence-v2"}))
    result = evaluate(run, gt, policy="strict-v3")
    assert not result.funnel["stages"]["confirmed"]["available"]
    assert result.scenario_score_pct is None
    assert result.score_unavailable_reason


@pytest.mark.parametrize("versions", [
    ("strict-v3.6", "evidence-v4"),
    (METRIC_CONTRACT_VERSION, "evidence-v4"),
])
def test_previous_proof_contract_is_not_promoted_or_rewritten(tmp_path, versions):
    a = finding("a", "192.0.2.1")
    run, gt = write_run(tmp_path, [a], [a], [confirmation(a)], records=[proof(a)])
    metadata = {"metric_contract_version": versions[0], "evidence_contract_version": versions[1]}
    metadata_path = run / "run_meta.json"
    metadata_path.write_text(json.dumps(metadata))
    before = metadata_path.read_bytes()
    result = evaluate(run, gt, policy="strict-v3")
    assert result.scenario_score_pct is None
    assert not result.funnel["stages"]["confirmed"]["available"]
    assert result.run_metric_contract_version == versions[0]
    assert result.run_evidence_contract_version == versions[1]
    assert result.score_unavailable_reason
    assert metadata_path.read_bytes() == before


def test_false_positive_without_gt_is_not_exempted_as_bonus(tmp_path):
    x = finding("x", "192.0.2.9")
    run, gt = write_run(tmp_path, [x], [x], [confirmation(x)], records=[proof(x)])
    data = yaml.safe_load(gt.read_text())
    data["bonus_types"] = ["data_exposure"]
    gt.write_text(yaml.safe_dump(data))
    result = evaluate(run, gt, policy="strict-v3")
    assert result.bonus_findings == 1  # legacy diagnostic, not a final-score exemption
    assert result.funnel["stages"]["confirmed"]["false_positives"] == 1


def test_severity_does_not_change_final_confirmation_f1(tmp_path):
    a = finding("a", "192.0.2.1")
    a["severity"] = "low"
    run, gt = write_run(tmp_path, [a], [a], [confirmation(a)], records=[proof(a)])
    result = evaluate(run, gt, policy="strict-v3")
    assert result.scenario_score_pct == 50.0
    assert result.severity_mismatches == 1


def test_macro_preserves_unavailable_stage_and_counts_are_explicit_means(tmp_path):
    a = finding("a", "192.0.2.1")
    run, gt = write_run(
        tmp_path, [a], [a], [confirmation(a)], records=[proof(a)],
        metadata=_COMPARABILITY_METADATA,
    )
    result = evaluate(run, gt, policy="strict-v3")
    summary = aggregate_evaluations([result, result])
    stage = summary["per_scenario"]["demo"]["funnel"]["stages"]["confirmed"]
    assert stage["predictions"] == 1  # mean per run, not sum
    assert stage["expected"] == stage["evaluated"] == 2
    (run / "04_exploitation.json").unlink()
    incomplete = evaluate(run, gt, policy="strict-v3")
    summary = aggregate_evaluations([result, incomplete])
    stage = summary["per_scenario"]["demo"]["funnel"]["stages"]["confirmed"]
    assert not stage["available"]
    assert stage["f1"] is None


def test_exact_duplicate_keeps_the_copy_with_supported_proof(tmp_path):
    a = finding("a", "192.0.2.1")
    b = dict(a, id="b")
    run, gt = write_run(tmp_path, [a, b], [a, b], [confirmation(a), confirmation(b)], records=[proof(b)])
    result = evaluate(run, gt, policy="strict-v3")
    stage = result.funnel["stages"]["confirmed"]
    assert stage["predictions"] == stage["true_positives"] == 1
    assert stage["invalid_evidence"] == 0
    assert result.phase4_candidates == result.phase4_conclusive == 1
    assert result.phase4_completion_rate == 1.0
    assert result.funnel["diagnostics"]["proofs"] == {
        "available": True, "accepted": 1, "rejected": 0, "missing": 0,
    }


def test_proof_diagnostics_separate_rejected_missing_and_valid_non_gt(tmp_path):
    a, b, x = [finding(name, f"192.0.2.{ip}") for name, ip in zip("abx", (1, 2, 9))]
    run, gt = write_run(tmp_path, [a, b, x], [a, b, x], [confirmation(f) for f in (a, b, x)], records=[
        proof(a, result={"status_code": 200, "body": "Welcome"}), proof(x),
    ])
    result = evaluate(run, gt, policy="strict-v3")
    assert result.funnel["diagnostics"]["proofs"] == {
        "available": True, "accepted": 1, "rejected": 1, "missing": 1,
    }
    assert result.funnel["stages"]["confirmed"]["true_positives"] == 0
    assert result.funnel["stages"]["confirmed"]["false_positives"] == 3
    (run / "tool_calls.jsonl").unlink()
    assert evaluate(run, gt, policy="strict-v3").funnel["diagnostics"]["proofs"] == {
        "available": False, "accepted": None, "rejected": None, "missing": None,
    }


@pytest.mark.parametrize("url", ["http://192.0.2.2/backup.sql", "http://192.0.2.1:8080/backup.sql", "http://192.0.2.1/login"])
def test_shared_proof_rules_do_not_bypass_evaluator_attribution(tmp_path, url):
    a = finding("a", "192.0.2.1")
    run, gt = write_run(tmp_path, [a], [a], [confirmation(a)], records=[proof(a, args={"url": url})])
    result = evaluate(run, gt, policy="strict-v3")
    assert result.funnel["stages"]["confirmed"]["true_positives"] == 0
    assert result.funnel["stages"]["confirmed"]["false_positives"] == 1


@pytest.mark.parametrize("has_valid_proof", [True, False])
def test_cost_and_turn_efficiency_share_final_valid_tp_denominator(tmp_path, has_valid_proof):
    a, b = finding("a", "192.0.2.1"), finding("b", "192.0.2.2")
    run, gt = write_run(tmp_path, [a, b], [a, b], [confirmation(a), confirmation(b)],
                        records=[proof(a)] if has_valid_proof else [])
    (run / "cost_summary.json").write_text(json.dumps({"total_cost_usd": 4.5, "total_turns": 18}))
    result = evaluate(run, gt, policy="strict-v3")
    assert result.funnel["stages"]["filtered"]["true_positives"] == 2
    assert result.funnel["stages"]["confirmed"]["true_positives"] == int(has_valid_proof)
    d = result.funnel["diagnostics"]
    assert d["cost_per_valid_confirmation"] == (4.5 if has_valid_proof else None)
    assert d["turns_per_valid_confirmation"] == (18 if has_valid_proof else None)


def test_model_ids_do_not_merge_different_targets_or_case_sensitive_paths():
    a = finding("same-id", "192.0.2.1")
    values = [a, dict(a), dict(a, device_ip="192.0.2.2"), dict(a, endpoint="/Backup.sql")]
    assert len(unique_predictions(values)) == 3


def test_configuration_confirmations_use_the_same_coverage_population(tmp_path):
    a = finding("a", "192.0.2.1")
    b = dict(finding("b", "192.0.2.2"), type="info_disclosure")
    run, gt = write_run(tmp_path, [a, b], [a, b], [confirmation(a), confirmation(b)], records=[
        proof(a), proof(b, result={"return_code": 0, "status_code": 200, "headers": {"Server": "nginx/1.22"}}),
    ])
    result = evaluate(run, gt, policy="strict-v3")
    assert result.phase4_conclusive == result.phase4_candidates == 2
    assert result.phase4_completion_rate == 1.0


def test_copying_benign_output_into_data_extracted_does_not_prove_a_leak(tmp_path):
    a = finding("a", "192.0.2.1")
    run, gt = write_run(tmp_path, [a], [a], [confirmation(a, data_extracted=["Welcome"])], records=[
        proof(a, result={"return_code": 0, "status_code": 200, "body": "Welcome"}),
    ])
    stage = evaluate(run, gt, policy="strict-v3").funnel["stages"]["confirmed"]
    assert stage["invalid_evidence"] == stage["false_positives"] == 1
    assert stage["true_positives"] == 0


@pytest.mark.parametrize("invalid_line", ["not json", "{}", "[]"])
def test_corrupt_provenance_does_not_produce_an_official_score(tmp_path, invalid_line):
    a = finding("a", "192.0.2.1")
    run, gt = write_run(tmp_path, [a], [a], [confirmation(a)], records=[proof(a)])
    log = run / "tool_calls.jsonl"
    log.write_text(log.read_text() + invalid_line + "\n")
    result = evaluate(run, gt, policy="strict-v3")
    assert result.scenario_score_pct is None
    assert not result.funnel["stages"]["confirmed"]["available"]
    assert result.funnel["stages"]["filtered"]["true_positives"] == 1


def test_zero_gt_control_scores_the_report_not_initial_hypotheses(tmp_path):
    x = finding("x", "192.0.2.9")
    run, gt = write_run(tmp_path, [x], [x], [{"vuln_id": "x", "status": "FAILED"}], truth=[], records=[])
    (run / "03_phase3_status.json").write_text(json.dumps({
        "status": "completed", "devices_total": 1, "devices_analyzed": 1, "devices_failed": [],
    }))
    result = evaluate(run, gt, policy="strict-v3")
    assert result.funnel["stages"]["candidates"]["false_positives"] == 1
    assert result.funnel["stages"]["confirmed"]["false_positives"] == 0
    assert result.funnel["stages"]["confirmed"]["f1"] is None
    assert result.scenario_score_pct == 100.0
    assert result.funnel["diagnostics"]["verification"]["inconclusive"] == 1


def test_funnel_is_not_aggregated_across_train_and_test_splits(tmp_path):
    a = finding("a", "192.0.2.1")
    run, gt = write_run(
        tmp_path, [a], [a], [confirmation(a)], records=[proof(a)],
        metadata=_COMPARABILITY_METADATA,
    )
    result = evaluate(run, gt, policy="strict-v3")
    summary = aggregate_evaluations([result, replace(result, scenario_id="other")], scenario_splits={"demo": "train", "other": "test"})
    assert summary["funnel"] is None
    assert summary["per_split"]["train"]["funnel"]["stages"]["confirmed"]["available"]
    assert summary["per_split"]["test"]["funnel"]["stages"]["confirmed"]["available"]


def test_missing_configuration_keeps_individual_scores_but_withholds_macro(tmp_path):
    a = finding("a", "192.0.2.1")
    (tmp_path / "known").mkdir()
    (tmp_path / "missing").mkdir()
    known_run, known_gt = write_run(
        tmp_path / "known", [a], [a], [confirmation(a)], records=[proof(a)],
        metadata=_COMPARABILITY_METADATA,
    )
    missing_run, missing_gt = write_run(
        tmp_path / "missing", [a], [a], [confirmation(a)], records=[proof(a)],
    )
    known = evaluate(known_run, known_gt, policy="strict-v3")
    missing = evaluate(missing_run, missing_gt, policy="strict-v3")
    individual_scores = (known.scenario_score_pct, missing.scenario_score_pct)

    aggregate = aggregate_evaluations([
        known, replace(missing, scenario_id="missing-config"),
    ])

    assert individual_scores == (50.0, 50.0)
    assert aggregate["macro_scenario_score_pct"] is None
    assert aggregate["per_scenario"]["demo"]["scenario_score_pct"] == 50.0
    assert aggregate["per_scenario"]["missing-config"]["comparability_status"] == "not_comparable"
