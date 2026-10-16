"""Verify offline archive integrity and prevent raw evidence exports."""
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"scripts/benchmark/{name}.py")
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


review = module("pilot_archive_review")
support = module("pilot_support")


def bundle(tmp_path):
    trial = tmp_path / "trial"
    run = tmp_path / "agent" / "2026-10-14_215415"
    trial.mkdir()
    run.mkdir(parents=True)
    (trial / "llm_dir.txt").write_text(str(run))
    (trial / "preflight-s15-r1-llm.json").write_text(json.dumps({
        "status": "valid", "evidence": "SECRET-RAW-CONTENT",
    }))
    (run / "run_meta.json").write_text(json.dumps({"status": "budget_exceeded", "max_tool_calls": 2}))
    (run / "cost_summary.json").write_text(json.dumps({"total_tool_calls": 2}))
    entry = {"tool": "http_get", "phase": 4, "args": {"url": "SECRET-RAW-CONTENT"},
             "result": "SECRET-RAW-CONTENT", "execution_origin": "runner"}
    (run / "tool_calls.jsonl").write_text((json.dumps(entry) + "\n") * 2)
    destination = tmp_path / "evidence"
    support.archive_trial(trial, run.parent, destination, "s15-r1")
    return destination


def test_review_verifies_all_files_and_exports_only_aggregate_calls(tmp_path):
    result = review.review_archive(bundle(tmp_path))
    assert "SECRET-RAW-CONTENT" not in json.dumps(result)
    assert result["verified_files"] == 5
    assert result["arms"]["rules"] == {"present": False}
    arm = result["arms"]["llm"]
    assert arm["status"] == "budget_exceeded"
    assert arm["calls_by_tool"] == {"http_get": 2}
    assert arm["calls_by_phase"] == {"4": 2}
    assert arm["repeated_tool_arguments"] == 1
    assert result["preflights"]["preflight-s15-r1-llm.json"]["human_validated"] is False


def test_modified_archive_is_rejected(tmp_path):
    directory = bundle(tmp_path)
    with (directory / "evidence.tar.gz").open("ab") as handle:
        handle.write(b"corruption")
    with pytest.raises(ValueError, match="Archive digest mismatch"):
        review.review_archive(directory)


def test_mismatched_file_digest_is_rejected_even_when_archive_matches(tmp_path):
    directory = bundle(tmp_path)
    path = directory / "evidence-manifest.json"
    manifest = json.loads(path.read_text())
    manifest["files"]["runs/2026-10-14_215415/tool_calls.jsonl"]["sha256"] = "0" * 64
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="Evidence file digest mismatch"):
        review.review_archive(directory)
