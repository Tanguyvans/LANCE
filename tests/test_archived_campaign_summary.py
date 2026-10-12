"""Tests for the offline archived-campaign summarizer.

All synthetic fixtures live under ``tmp_path``; the local-archive test only
reads the existing ``output/validation`` evidence and writes its summary to
``tmp_path``. No network, no pipeline imports, no archive execution.
"""

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "analysis" \
    / "summarize_archived_campaign.py"
LOCAL_ARCHIVE = Path(__file__).resolve().parent.parent / "output" \
    / "validation" / "2026-10-04-qwen-umons"

PHASES = ("graph_analysis", "recon", "vuln_analysis", "exploitation",
          "intrusion", "report")


def load_module():
    spec = importlib.util.spec_from_file_location(
        "summarize_archived_campaign", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mod = load_module()


def write_json(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(payload, (dict, list)):
        path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    else:
        path.write_text(payload, encoding="utf-8")


def make_run(root, run_id, scenario="3", status="completed",
             phases=None, score_f1=0.622, score_available=True,
             commit="abc123", with_score_meta=True, cleanup="completed",
             phase3=None, lifecycle_errors=None, usage_errors=None):
    rundir = root / run_id
    rundir.mkdir(parents=True, exist_ok=True)
    results = {p: "completed" for p in PHASES}
    if phases:
        results.update(phases)
    run_meta = {
        "status": status, "cleanup_status": cleanup, "results": results,
        "git_commit": commit, "metric_contract_version": "strict-v3.16",
        "evidence_contract_version": "evidence-v15",
        "lifecycle_errors": lifecycle_errors or [],
        "usage_errors": usage_errors or [],
    }
    write_json(rundir / "run_meta.json", run_meta)
    write_json(rundir / "scenario_meta.json", {
        "scenario_id": scenario, "git_commit": commit})
    if phase3 is not None:
        write_json(rundir / "03_phase3_status.json", phase3)
    if with_score_meta:
        confirmed = {"available": score_available, "f1": score_f1,
                     "true_positives": 14, "false_positives": 13,
                     "false_negatives": 4, "precision": 0.519,
                     "recall": 0.778}
        write_json(rundir / "score.json", {
            "scenario_id": scenario,
            "metric_contract_version": "strict-v3.16",
            "evidence_contract_version": "evidence-v15",
            "score_unavailable_reason": None,
            "total_gt_vulns": 18,
            "funnel": {"stages": {"confirmed": confirmed}},
        })
    return rundir


def codes(summary, run_id=None):
    return [w["code"] for w in summary["warnings"]
            if run_id is None or w["run_id"] == run_id]


def run_cli(*argv):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *argv],
        capture_output=True, text=True, timeout=120)


# --- core behavior on synthetic archives ------------------------------------


def test_complete_run_lifecycle_recorded_and_score_verbatim(tmp_path):
    make_run(tmp_path, "2026-10-05_134540", scenario="3", score_f1=0.622)
    summary = mod.build_summary(tmp_path, ["2026-10-05_134540"])
    assert len(summary["runs"]) == 1
    entry = summary["runs"][0]
    assert entry["scenario"] == "3"
    assert entry["status_recorded"] == "completed"
    assert entry["six_phases_complete"] is True
    assert entry["lifecycle_complete_recorded"] is True
    assert entry["score_confirmed"]["f1"] == 0.622
    assert entry["score_explanation"] is None
    assert entry["commit"] == "abc123"
    assert "stale_completed_status" not in codes(summary, entry["run_id"])


def test_stale_completed_with_failed_phase_not_recorded_complete(tmp_path):
    make_run(tmp_path, "run-stale", scenario="5", status="completed",
             phases={"recon": "failed:Recorded reconnaissance incomplete"})
    summary = mod.build_summary(tmp_path, ["run-stale"])
    entry = summary["runs"][0]
    assert entry["status_recorded"] == "completed"
    assert entry["six_phases_complete"] is False
    assert entry["lifecycle_complete_recorded"] is False
    assert "stale_completed_status" in codes(summary, "run-stale")


@pytest.mark.parametrize("cleanup", ["pending", "failed", "not_required"])
def test_completed_phases_with_bad_cleanup_not_recorded_complete(
        tmp_path, cleanup):
    make_run(tmp_path, "run-cleanup", scenario="2", status="completed",
             cleanup=cleanup)
    summary = mod.build_summary(tmp_path, ["run-cleanup"])
    entry = summary["runs"][0]
    assert entry["six_phases_complete"] is True
    assert entry["cleanup_status"] == cleanup
    assert entry["lifecycle_complete_recorded"] is False
    assert "lifecycle_completion_refused" in codes(summary, "run-cleanup")
    assert "cleanup_status" in summary["warnings"][0]["message"]


def test_contradictory_phase3_failures_refuse_completion(tmp_path):
    make_run(tmp_path, "run-p3", scenario="4", status="completed",
             phase3={"status": "completed_with_device_errors",
                     "devices_total": 8, "devices_analyzed": 7,
                     "devices_failed": [{"device_id": "s4-router"}],
                     "scanner_errors": ["s4-router: no scanner rule"]})
    summary = mod.build_summary(tmp_path, ["run-p3"])
    entry = summary["runs"][0]
    assert entry["six_phases_complete"] is True
    assert entry["lifecycle_complete_recorded"] is False
    assert "lifecycle_completion_refused" in codes(summary, "run-p3")
    message = " ".join(w["message"] for w in summary["warnings"])
    assert "devices_failed" in message
    assert "scanner_errors" in message
    # Raw recorded values stay independently visible.
    assert entry["status_recorded"] == "completed"
    assert entry["diagnostics"]["phase3_status"]["status"] == \
        "completed_with_device_errors"


def test_partial_phase3_scanner_errors_are_preserved_verbatim(tmp_path):
    repeated = "s11-gw1: LLM request deadline exceeded; " \
        "s11-gw1: LLM request deadline exceeded"
    phase3 = {
        "status": "completed_with_device_errors",
        "devices_total": 15,
        "devices_analyzed": 14,
        "devices_failed": [],
        "scanner_errors": [repeated],
    }
    make_run(tmp_path, "run-partial-scanner", status="partial",
             phases={"report": "running"}, phase3=phase3,
             with_score_meta=False)

    entry = mod.build_summary(tmp_path, ["run-partial-scanner"])["runs"][0]

    assert entry["diagnostics"]["phase3_status"]["scanner_errors"] == [repeated]
    assert entry["score_confirmed"] is None


def test_absent_scanner_errors_remain_absent_in_phase3_projection(tmp_path):
    make_run(tmp_path, "run-scanner-field-absent", status="partial",
             phases={"report": "running"},
             phase3={"status": "running", "devices_total": 2},
             with_score_meta=False)

    entry = mod.build_summary(tmp_path, ["run-scanner-field-absent"])["runs"][0]

    assert "scanner_errors" not in entry["diagnostics"]["phase3_status"]
    assert entry["score_confirmed"] is None


def test_recorded_lifecycle_errors_refuse_completion(tmp_path):
    make_run(tmp_path, "run-err", scenario="6", status="completed",
             lifecycle_errors=["teardown timeout"],
             usage_errors=["budget overrun"])
    summary = mod.build_summary(tmp_path, ["run-err"])
    entry = summary["runs"][0]
    assert entry["lifecycle_complete_recorded"] is False
    assert "lifecycle_completion_refused" in codes(summary, "run-err")
    assert entry["diagnostics"]["lifecycle_errors"] == ["teardown timeout"]
    assert entry["diagnostics"]["usage_errors"] == ["budget overrun"]


def test_missing_score_uses_failure_json_schema_not_zero(tmp_path):
    """Actual failure-JSON shapes: score-unavailable-response + run_error."""
    rundir = make_run(tmp_path, "run-s12", scenario="12", status="failed",
                      phases={"graph_analysis": "failed:truncated_output",
                              "recon": "skipped:prerequisites"},
                      with_score_meta=False)
    (rundir / "score.json").unlink(missing_ok=True)
    write_json(rundir / "score-unavailable-response.json", {
        "observed_at": "2026-10-05T04:57:57.158837+00:00",
        "http_status": 404,
        "body": {"detail": "03_vuln_analysis.json not found — run Phase 3 first"},
        "reason": "Official endpoint response; no fabricated score.",
    })
    write_json(rundir / "run_error.json", {
        "schema_version": 1, "phase": "graph_analysis",
        "exception_class": "APIConnectionError",
        "exception_module": "openai", "message": "Connection error.",
    })
    summary = mod.build_summary(tmp_path, ["run-s12"])
    entry = summary["runs"][0]
    assert entry["score_confirmed"] is None
    assert entry["score_confirmed"] != 0
    assert "404" in entry["score_explanation"]
    assert "graph_analysis" in entry["score_explanation"]
    assert entry["diagnostics"]["score_unavailable_response"]["http_status"] == 404
    assert entry["diagnostics"]["run_error"]["phase"] == "graph_analysis"


def test_status_code_with_encoded_string_body_restores_status_and_detail(
        tmp_path):
    """Archived S12 form: status_code + JSON-encoded string body."""
    rundir = make_run(tmp_path, "run-s12b", scenario="12", status="failed",
                      phases={"graph_analysis": "failed:truncated_output"},
                      with_score_meta=False)
    (rundir / "score.json").unlink(missing_ok=True)
    write_json(rundir / "score-unavailable-response.json", {
        "status_code": 404,
        "endpoint": "/api/runs/2026-10-05_114742/score",
        "body": '{"detail":"03_vuln_analysis.json not found '
                '\u2014 run Phase 3 first"}',
        "reason": "Official score unavailable; no zero score synthesized.",
    })
    summary = mod.build_summary(tmp_path, ["run-s12b"])
    entry = summary["runs"][0]
    assert entry["score_confirmed"] is None
    assert entry["score_confirmed"] != 0
    assert "404" in entry["score_explanation"]
    assert "03_vuln_analysis.json not found" in entry["score_explanation"]
    diag = entry["diagnostics"]["score_unavailable_response"]
    assert diag["http_status"] == 404
    assert diag["status_code"] == 404
    assert diag["detail"] == \
        "03_vuln_analysis.json not found \u2014 run Phase 3 first"
    assert "score_unavailable_status_conflict" not in codes(
        summary, "run-s12b")


def test_conflicting_status_keys_flagged_with_both_preserved(tmp_path):
    rundir = make_run(tmp_path, "run-conflict", scenario="12",
                      status="failed", with_score_meta=False)
    (rundir / "score.json").unlink(missing_ok=True)
    write_json(rundir / "score-unavailable-response.json", {
        "http_status": 200,
        "status_code": 404,
        "body": {"detail": "ambiguous record"},
        "reason": "Official score unavailable; no zero score synthesized.",
    })
    summary = mod.build_summary(tmp_path, ["run-conflict"])
    entry = summary["runs"][0]
    assert entry["score_confirmed"] is None
    assert entry["score_confirmed"] != 0
    assert "score_unavailable_status_conflict" in codes(
        summary, "run-conflict")
    diag = entry["diagnostics"]["score_unavailable_response"]
    assert diag["http_status"] == 200
    assert diag["status_code"] == 404
    assert diag["detail"] == "ambiguous record"


def test_invalid_http_status_falls_back_to_valid_status_code(tmp_path):
    rundir = make_run(tmp_path, "run-invalid-http-status", scenario="12",
                      status="failed", with_score_meta=False)
    (rundir / "score.json").unlink(missing_ok=True)
    write_json(rundir / "score-unavailable-response.json", {
        "http_status": "not-a-status",
        "status_code": 404,
        "body": {"detail": "score unavailable"},
    })

    summary = mod.build_summary(tmp_path, ["run-invalid-http-status"])
    entry = summary["runs"][0]

    assert "status_code=404" in entry["score_explanation"]
    assert "http_status=None" not in entry["score_explanation"]
    diag = entry["diagnostics"]["score_unavailable_response"]
    assert diag["http_status"] == 404
    assert diag["status_code"] == 404


def test_malformed_string_body_neither_raises_nor_guesses(tmp_path):
    rundir = make_run(tmp_path, "run-badbody", scenario="12",
                      status="failed", with_score_meta=False)
    (rundir / "score.json").unlink(missing_ok=True)
    write_json(rundir / "score-unavailable-response.json", {
        "status_code": 404,
        "body": "{not valid json,,,",
        "reason": "Official score unavailable; no zero score synthesized.",
    })
    summary = mod.build_summary(tmp_path, ["run-badbody"])
    entry = summary["runs"][0]
    assert entry["score_confirmed"] is None
    assert entry["score_confirmed"] != 0
    assert "404" in entry["score_explanation"]
    assert "detail=" not in entry["score_explanation"]
    diag = entry["diagnostics"]["score_unavailable_response"]
    assert diag["http_status"] == 404
    assert diag["detail"] is None


def test_absent_status_keys_stay_null_without_conflict(tmp_path):
    rundir = make_run(tmp_path, "run-nostatus", scenario="12",
                      status="failed", with_score_meta=False)
    (rundir / "score.json").unlink(missing_ok=True)
    write_json(rundir / "score-unavailable-response.json", {
        "body": {"detail": "no status recorded"},
        "reason": "Official score unavailable; no zero score synthesized.",
    })
    summary = mod.build_summary(tmp_path, ["run-nostatus"])
    entry = summary["runs"][0]
    assert entry["score_confirmed"] is None
    diag = entry["diagnostics"]["score_unavailable_response"]
    assert diag["http_status"] is None
    assert diag["status_code"] is None
    assert diag["detail"] == "no status recorded"
    assert "score_unavailable_status_conflict" not in codes(
        summary, "run-nostatus")


def test_scenario_from_run_meta_when_no_score(tmp_path):
    rundir = tmp_path / "run-nometa"
    rundir.mkdir()
    write_json(rundir / "run_meta.json", {
        "status": "failed", "cleanup_status": "not_required", "results": {},
        "scenario_id": "7", "git_commit": "e9d7d55"})
    summary = mod.build_summary(tmp_path, ["run-nometa"])
    entry = summary["runs"][0]
    assert entry["scenario"] == "7"
    assert entry["score_confirmed"] is None


@pytest.mark.parametrize("filename", ["score.json", "run_meta.json",
                                      "scenario_meta.json"])
def test_malformed_files_are_flagged_not_fatal(tmp_path, filename):
    rundir = make_run(tmp_path, "run-bad", scenario="4")
    write_json(rundir / filename, "{not valid json,,,")
    summary = mod.build_summary(tmp_path, ["run-bad"])
    assert len(summary["runs"]) == 1
    assert "malformed_file" in codes(summary, "run-bad")
    if filename == "score.json":
        assert summary["runs"][0]["score_confirmed"] is None


def test_score_meta_scenario_mismatch_detected(tmp_path):
    rundir = make_run(tmp_path, "run-mix", scenario="4")
    score = json.loads((rundir / "score.json").read_text())
    score["scenario_id"] = "3"
    write_json(rundir / "score.json", score)
    summary = mod.build_summary(tmp_path, ["run-mix"])
    assert "score_meta_scenario_mismatch" in codes(summary, "run-mix")
    entry = summary["runs"][0]
    assert entry["scenario_sources"]["score"] == "3"
    assert entry["scenario_sources"]["scenario_meta"] == "4"


def test_distinct_runs_preserve_commit_and_contracts(tmp_path):
    make_run(tmp_path, "run-a", scenario="2", commit="base111")
    rundir_b = make_run(tmp_path, "run-b", scenario="2", commit="fix222")
    score = json.loads((rundir_b / "score.json").read_text())
    score["metric_contract_version"] = "strict-v3.16"
    write_json(rundir_b / "score.json", score)
    meta = json.loads((rundir_b / "run_meta.json").read_text())
    meta["metric_contract_version"] = "strict-v3.16"
    write_json(rundir_b / "run_meta.json", meta)
    summary = mod.build_summary(tmp_path, ["run-a", "run-b"])
    by_id = {e["run_id"]: e for e in summary["runs"]}
    assert set(by_id) == {"run-a", "run-b"}
    assert by_id["run-a"]["commit"] == "base111"
    assert by_id["run-b"]["commit"] == "fix222"
    assert by_id["run-b"]["contracts"]["score_metric_contract"] == "strict-v3.16"


def test_scope_exclusion_by_scenario(tmp_path):
    make_run(tmp_path, "run-s3", scenario="3")
    make_run(tmp_path, "run-s13", scenario="13", status="failed",
             phases={"graph_analysis": "failed:exception"})
    summary = mod.build_summary(tmp_path, ["run-s3", "run-s13"],
                                scenarios="1-12")
    assert [e["run_id"] for e in summary["runs"]] == ["run-s3"]
    assert len(summary["excluded"]) == 1
    assert summary["excluded"][0]["run_id"] == "run-s13"
    assert summary["excluded"][0]["exclusion_reason"] == "scenario_out_of_scope"


def test_diagnostic_runs_kept_separate(tmp_path):
    make_run(tmp_path, "run-official", scenario="1")
    make_run(tmp_path, "run-diag", scenario="1")
    summary = mod.build_summary(tmp_path, ["run-official", "run-diag"],
                                diagnostic_runs=["run-diag"])
    by_id = {e["run_id"]: e for e in summary["runs"]}
    assert by_id["run-diag"]["group"] == "diagnostic"
    assert by_id["run-official"]["group"] == "official"


def test_only_explicit_runs_selected_never_by_mtime(tmp_path):
    make_run(tmp_path, "run-wanted", scenario="1")
    make_run(tmp_path, "run-unlisted", scenario="1")
    summary = mod.build_summary(tmp_path, ["run-wanted"])
    assert [e["run_id"] for e in summary["runs"]] == ["run-wanted"]


@pytest.mark.parametrize("bad_id", ["../escape", "a/b", "", ".", "/abs",
                                    "has space?", "semi;colon", "star*id"])
def test_unsafe_run_ids_rejected(tmp_path, bad_id):
    with pytest.raises(mod.SummaryError):
        mod.build_summary(tmp_path, [bad_id])


def test_symlink_outside_root_not_followed(tmp_path):
    root = tmp_path / "archive"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "secret-score.json"
    write_json(sentinel, {
        "scenario_id": "9", "metric_contract_version": "strict-v3.16",
        "evidence_contract_version": "evidence-v15",
        "total_gt_vulns": 99,
        "funnel": {"stages": {"confirmed": {"available": True, "f1": 1.0}}}})
    rundir = make_run(root, "run-link", scenario="9",
                      with_score_meta=False)
    (rundir / "score.json").unlink(missing_ok=True)
    (rundir / "score.json").symlink_to(sentinel)
    summary = mod.build_summary(root, ["run-link"])
    text = json.dumps(summary)
    assert "secret-score" not in text
    assert summary["runs"][0]["score_confirmed"] is None
    assert "symlink_outside_root" in codes(summary, "run-link")


def test_output_inside_archive_or_over_input_refused(tmp_path):
    make_run(tmp_path, "run-x", scenario="1")
    inside = str(tmp_path / "run-x" / "summary.json")
    proc = run_cli("--archive-root", str(tmp_path), "--run", "run-x",
                   "--output", inside)
    assert proc.returncode == 2
    victim = tmp_path / "out.json"
    victim.write_text("{}\n", encoding="utf-8")
    proc = run_cli("--archive-root", str(tmp_path), "--run", "run-x",
                   "--output", str(victim))
    assert proc.returncode == 2  # exists without --overwrite
    assert not (tmp_path / "run-x" / "summary.json").exists()


def test_deterministic_content(tmp_path):
    make_run(tmp_path, "run-a", scenario="2")
    make_run(tmp_path, "run-b", scenario="3", status="failed",
             phases={"recon": "failed:x"})
    first = mod.build_summary(tmp_path, ["run-a", "run-b"])
    second = mod.build_summary(tmp_path, ["run-b", "run-a"])
    assert (json.dumps(first, sort_keys=True)
            == json.dumps(second, sort_keys=True))


def test_review_recorded_separately_without_touching_scores(tmp_path):
    rundir = make_run(tmp_path, "run-s3", scenario="3", score_f1=0.622)
    review = tmp_path / "s3-review.json"
    write_json(review, {"scenario": "3", "run_id": "run-s3",
                        "status": "reviewed", "confirmed_funnel": {"f1": 0.1}})
    summary = mod.build_summary(tmp_path, ["run-s3"], reviews=[str(review)])
    assert summary["runs"][0]["score_confirmed"]["f1"] == 0.622
    assert summary["supplemental_reviews"][0]["header"]["run_id"] == "run-s3"
    assert summary["supplemental_reviews"][0]["sha256"] is not None
    assert rundir.joinpath("score.json").exists()


def test_stdout_is_pure_json_with_diagnostics_on_stderr(tmp_path):
    make_run(tmp_path, "run-out", scenario="1")
    proc = run_cli("--archive-root", str(tmp_path), "--run", "run-out",
                   "--output", "-")
    assert proc.returncode == 0, proc.stderr
    parsed = json.loads(proc.stdout)  # invalid JSON fails here
    assert parsed["runs"][0]["run_id"] == "run-out"
    assert "runs=" in proc.stderr


def test_output_refuses_manifest_and_review_aliases(tmp_path):
    root = tmp_path / "archive"
    make_run(root, "run-m", scenario="1")
    manifest = tmp_path / "manifest.json"
    write_json(manifest, {"runs": ["run-m"]})
    review = tmp_path / "review.json"
    write_json(review, {"run_id": "run-m", "status": "reviewed"})
    manifest_before = manifest.read_bytes()
    review_before = review.read_bytes()
    # Select run-m exactly once, via the manifest: any duplicate selection
    # would fail before output protection is exercised.
    base = ["--archive-root", str(root),
            "--manifest", str(manifest), "--review", str(review)]
    for target in (str(manifest), str(review)):
        proc = run_cli(*base, "--output", target, "--overwrite")
        assert proc.returncode == 2, target
        assert "consumed input" in proc.stderr, (target, proc.stderr)
    alias = tmp_path / "alias-review.json"
    alias.symlink_to(review)
    proc = run_cli(*base, "--output", str(alias), "--overwrite")
    assert proc.returncode == 2
    assert "consumed input" in proc.stderr, proc.stderr
    assert manifest.read_bytes() == manifest_before
    assert review.read_bytes() == review_before


def test_output_refuses_hardlink_alias(tmp_path):
    root = tmp_path / "archive"
    rundir = make_run(root, "run-h", scenario="1")
    victim = rundir / "score.json"
    link = tmp_path / "hardlink.json"
    try:
        os.link(victim, link)
    except OSError:
        pytest.skip("hardlinks unsupported here")
    out = tmp_path / "out.json"
    out.write_bytes(b"{}\n")
    proc = run_cli("--archive-root", str(root), "--run", "run-h",
                   "--output", str(link), "--overwrite")
    assert proc.returncode == 2
    assert json.loads(victim.read_text())["scenario_id"] == "1"


def test_fixed_tmp_sentinel_survives_and_output_written(tmp_path):
    root = tmp_path / "archive"
    make_run(root, "run-t", scenario="1")
    out = tmp_path / "summary.json"
    sentinel = tmp_path / "summary.json.tmp"
    sentinel.write_text("sentinel", encoding="utf-8")
    proc = run_cli("--archive-root", str(root), "--run", "run-t",
                   "--output", str(out))
    assert proc.returncode == 0, proc.stderr
    assert sentinel.read_text() == "sentinel"
    assert json.loads(out.read_text())["runs"][0]["run_id"] == "run-t"


def test_symlink_loop_is_a_warning_not_a_crash(tmp_path):
    root = tmp_path / "archive"
    rundir = make_run(root, "run-loop", scenario="2", with_score_meta=False)
    loop_a = rundir / "score.json"
    loop_b = rundir / "loop-b.json"
    loop_a.symlink_to(loop_b)
    loop_b.symlink_to(loop_a)
    summary = mod.build_summary(root, ["run-loop"])
    assert summary["runs"][0]["score_confirmed"] is None
    assert summary["warnings"], "expected a warning for the symlink loop"


def test_manifest_with_invalid_list_types_rejected(tmp_path):
    bad_runs = tmp_path / "bad-runs.json"
    write_json(bad_runs, {"runs": "run-a"})
    with pytest.raises(mod.SummaryError):
        mod.load_manifest(bad_runs)
    bad_diag = tmp_path / "bad-diag.json"
    write_json(bad_diag, {"runs": ["run-a"], "diagnostic_runs": {"x": 1}})
    with pytest.raises(mod.SummaryError):
        mod.load_manifest(bad_diag)
    bad_item = tmp_path / "bad-item.json"
    write_json(bad_item, {"runs": ["run-a", 42]})
    with pytest.raises(mod.SummaryError):
        mod.load_manifest(bad_item)


def test_malformed_score_wording_differs_from_absent(tmp_path):
    rundir = make_run(tmp_path, "run-malf", scenario="4",
                      with_score_meta=False)
    write_json(rundir / "score.json", "{broken")
    summary = mod.build_summary(tmp_path, ["run-malf"])
    entry = summary["runs"][0]
    assert entry["score_confirmed"] is None
    assert "malformed" in entry["score_explanation"]
    assert "absent from archive" not in entry["score_explanation"]
    rundir2 = make_run(tmp_path, "run-abs", scenario="4",
                       with_score_meta=False)
    summary2 = mod.build_summary(tmp_path, ["run-abs"])
    assert "absent from archive" in \
        summary2["runs"][0]["score_explanation"]


def test_unreadable_file_warns_without_crash(tmp_path):
    root = tmp_path / "archive"
    rundir = make_run(root, "run-perm", scenario="5", with_score_meta=False)
    target = rundir / "score.json"
    target.write_text("{}\n", encoding="utf-8")
    target.chmod(0o000)
    try:
        if os.access(target, os.R_OK):
            pytest.skip("file still readable (e.g. privileged user)")
        summary = mod.build_summary(root, ["run-perm"])
    finally:
        target.chmod(0o644)
    assert summary["runs"][0]["score_confirmed"] is None
    assert "unreadable_file" in codes(summary, "run-perm")


# --- offline CLI on the real local archives ---------------------------------


def _hash_tree(paths):
    out = {}
    for path in paths:
        if path.is_file() and not path.is_symlink():
            out[str(path)] = hashlib.sha256(
                path.read_bytes()).hexdigest()
    return out


def test_cli_on_local_archives_with_explicit_runs(tmp_path):
    if not LOCAL_ARCHIVE.is_dir():
        pytest.skip("local validation archive not present")
    runs = ["2026-10-05_134540", "2026-10-05_114742", "2026-10-05_050020"]
    for run_id in runs:
        if not (LOCAL_ARCHIVE / run_id).is_dir():
            pytest.skip(f"archived run {run_id} not present")
    before = _hash_tree([p for r in runs
                         for p in (LOCAL_ARCHIVE / r).rglob("*")])
    out1 = tmp_path / "summary1.json"
    out2 = tmp_path / "summary2.json"
    args = ["--archive-root", str(LOCAL_ARCHIVE),
            "--run", "2026-10-05_134540",
            "--run", "2026-10-05_114742",
            "--run", "2026-10-05_050020",
            "--scenarios", "1-12"]
    proc = run_cli(*args, "--output", str(out1))
    assert proc.returncode == 0, proc.stderr
    proc = run_cli(*args, "--output", str(out2))
    assert proc.returncode == 0, proc.stderr
    # Deterministic content aside from the optional observation time.
    assert out1.read_bytes() == out2.read_bytes()
    after = _hash_tree([p for r in runs
                        for p in (LOCAL_ARCHIVE / r).rglob("*")])
    assert before == after  # inputs read-only, hashes unchanged

    summary = json.loads(out1.read_text(encoding="utf-8"))
    by_id = {e["run_id"]: e for e in summary["runs"]}
    # S3 corrective run: recorded lifecycle complete, score preserved.
    s3 = by_id["2026-10-05_134540"]
    assert s3["scenario"] == "3"
    assert s3["six_phases_complete"] is True
    assert s3["lifecycle_complete_recorded"] is True
    expected_f1 = json.loads(
        (LOCAL_ARCHIVE / "2026-10-05_134540" / "score.json")
        .read_text(encoding="utf-8"))["funnel"]["stages"]["confirmed"]["f1"]
    assert s3["score_confirmed"]["f1"] == expected_f1
    # S12 corrective failure: missing score is null with explanation, not 0.
    s12 = by_id["2026-10-05_114742"]
    assert s12["score_confirmed"] is None
    assert s12["score_confirmed"] != 0
    assert s12["score_explanation"]
    # S13 is outside S1-S12 scope: excluded, never scored.
    assert [e["run_id"] for e in summary["excluded"]] == ["2026-10-05_050020"]
    assert summary["excluded"][0]["scenario"] == "13"
