"""Do not turn cumulative artifacts, cancelled jobs or retries into new pairs."""
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("reconcile_pilot", ROOT / "scripts/benchmark/reconcile_pilot.py")
reconcile = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reconcile)


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


def attempt(root, rid, *, started=True, status="success", comparison=True):
    item = {"databaseId": rid, "attempt": 1, "workflow": "pilot-campaign.yml",
            "createdAt": "2026-10-14T13:17:00Z", "headSha": "a" * 40,
            "conclusion": status, "url": f"https://github.com/example/repo/actions/runs/{rid}"}
    directory = root / "actions" / str(rid)
    directory.mkdir(parents=True)
    lines = ["2026-10-14T13:17:01Z trial=s1-r1 instance=s1"]
    if started:
        lines += ["2026-10-14T13:20:00Z == arm 1: rules ==", "2026-10-14T13:24:00Z == arm 2: llm ==",
                  "2026-10-14T13:25:00Z rules_dir=output/agent/2026-10-14_152000 llm_dir=output/agent/2026-10-14_152400"]
    (directory / "workflow.log").write_text("\n".join(lines))
    write(directory / "artifacts-index.json", [{"id": 1, "name": "example"}])
    # Even a cancelled job can upload a previous pair's successful comparison.
    write(directory / "artifacts/comparison-s1-r1.json", {
        "comparable": comparison, "raw": "SECRET-RAW-CONTENT", "arms": {
            p: {"run_dir": f"output/agent/2026-10-14_{name}", "status": "completed",
                "evaluation": {"comparability_identity": {"resource_manifest_sha256": "b" * 64}}}
            for p, name in [("rules", "152000"), ("llm", "152400")]}})
    return item


def plan():
    return {"campaign_id": "pilot", "configuration": {"resource_manifest_sha256": "b" * 64},
            "trials": [{"trial_id": "s1-r1"}, {"trial_id": "s1-r2"}]}


def test_cancelled_attempt_does_not_reuse_cumulative_success(tmp_path):
    item = attempt(tmp_path, 10, started=False, status="cancelled")
    result = reconcile.reconcile_attempt(tmp_path, item, {})
    assert result["arms"] == {}
    assert result["published_comparable"] is None
    assert result["trial_id"] == "s1-r1"


def test_retry_failure_and_original_success_are_both_retained(tmp_path):
    first = attempt(tmp_path, 10)
    second = attempt(tmp_path, 11, comparison=False)
    # Give the retry its own actual run directories.
    directory = tmp_path / "actions/11"
    for path in [directory / "workflow.log", directory / "artifacts/comparison-s1-r1.json"]:
        path.write_text(path.read_text().replace("152000", "162000").replace("152400", "162400"))
    write(tmp_path / "actions-inventory.json", [first, second])
    result = reconcile.reconcile(tmp_path, plan())
    assert result["frozen_execution_attempts"] == 2
    assert result["planned_pairs_with_frozen_execution"] == 1
    assert result["published_comparable_frozen_attempts"] == 1
    assert len(result["planned_trials"][0]["attempt_ids"]) == 2
    assert result["planned_trials"][1]["status"] == "not_executed_under_freeze"
    assert "SECRET-RAW-CONTENT" not in json.dumps(result)
    assert result["resources_campaign_and_smoke"]["llm"]["total_cost_usd"]["complete_total"] is None


def test_reference_correction_requires_policy_trial_and_creation_boundary(tmp_path):
    item = attempt(tmp_path, 10)
    directory = tmp_path / "actions/10"
    for path in [directory / "workflow.log", directory / "artifacts/comparison-s1-r1.json"]:
        path.write_text(path.read_text().replace("2026-10-14_152400", ".benchmark-score-cache"))
    recovered = {name: {"run": name, "not_found_on_api": True, "trial_id": trial, "policy": policy}
                 for name, trial, policy in [("2026-10-14_152400", "s1-r1", "llm"),
                                             ("2026-10-14_152401", "s1-r2", "llm"),
                                             ("2026-10-14_152402", "s1-r1", "rules"),
                                             ("2026-10-14_162400", "s1-r1", "llm")]}
    result = reconcile.reconcile_attempt(tmp_path, item, recovered)
    assert result["arms"]["llm"]["run"] == "2026-10-14_152400"
    assert result["reference_corrections"]["llm"]["published_reference"] == ".benchmark-score-cache"


def test_ambiguous_reference_is_not_replaced_by_a_guessed_run(tmp_path):
    item = attempt(tmp_path, 10)
    path = tmp_path / "actions/10/workflow.log"
    path.write_text(path.read_text().replace("2026-10-14_152400", ".benchmark-score-cache"))
    recovered = {name: {"run": name, "not_found_on_api": True, "trial_id": "s1-r1", "policy": "llm"}
                 for name in ["2026-10-14_152400", "2026-10-14_152401"]}
    result = reconcile.reconcile_attempt(tmp_path, item, recovered)
    assert result["reference_corrections"] == {}
    assert result["published_comparable"] is None


def test_same_execution_cannot_count_twice(tmp_path):
    write(tmp_path / "actions-inventory.json", [attempt(tmp_path, 10), attempt(tmp_path, 11)])
    with pytest.raises(ValueError, match="Run reused"):
        reconcile.reconcile(tmp_path, plan())
