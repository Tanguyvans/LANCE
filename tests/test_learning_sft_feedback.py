from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.learning.sft_feedback import (
    FeedbackConversionError,
    convert_feedback,
    convert_feedback_by_expert,
)


def _write_jsonl(path: Path, records: list[dict]) -> Path:
    path.write_text("\n".join(json.dumps(item) for item in records) + "\n")
    return path


def _accepted(candidate_id: str, **overrides) -> dict:
    candidate = {
        "candidate_id": candidate_id,
        "task": "deliverable_correction",
        "expert": "recon",
        "phase": 2,
        "input": {"draft_deliverable": "draft", "evidence": ["tcp/80 open"]},
        "target": {
            "expected_deliverable": {
                "filename": "02_recon.md",
                "content": "# Recon\n\n- tcp/80 open",
            }
        },
        "review": {"status": "accepted", "reviewer": "test", "notes": "verified"},
        "occurrences": [{"run_id": "run-1"}],
    }
    candidate.update(overrides)
    return candidate


def _trace(path: Path) -> dict:
    return json.loads(path.read_text().splitlines()[0])


def _save_arguments(trace: dict) -> dict:
    return trace["messages"][-1]["tool_calls"][0]["function"]["arguments"]


def test_generic_feedback_routes_each_expert_and_phase(tmp_path: Path):
    candidates = [
        _accepted(
            "secretary-1",
            expert="secretary",
            phase=1,
            target={
                "expected_deliverable": {
                    "filename": "01_graph_analysis.md",
                    "content": "# Corrected graph",
                }
            },
        ),
        _accepted("recon-1"),
        _accepted(
            "exploit-1",
            expert="exploit",
            phase=4,
            target={
                "expected_deliverable": {
                    "filename": "04_exploits/device/VULN-1.json",
                    "content": {"status": "FAILED", "evidence": "timeout"},
                }
            },
        ),
        _accepted(
            "exploit-2",
            task="exploit_correction",
            expert="ignored-because-task-is-explicit",
            phase=5,
            target={
                "expected_deliverable": {
                    "filename": "05_intrusion.json",
                    "content": {"compromised_hosts": []},
                }
            },
        ),
    ]
    source = _write_jsonl(tmp_path / "accepted.jsonl", candidates)

    result = convert_feedback_by_expert(source, tmp_path / "runs", tmp_path / "out")

    assert result["counts_by_expert"] == {"exploit": 2, "recon": 1, "secretary": 1}
    for expert, count in result["counts_by_expert"].items():
        records = (tmp_path / "out" / f"{expert}_feedback_accepted.jsonl").read_text()
        assert len(records.splitlines()) == count
        assert all(json.loads(line)["metadata"]["expert"] == expert for line in records.splitlines())
    exploit = _trace(tmp_path / "out" / "exploit_feedback_accepted.jsonl")
    assert json.loads(_save_arguments(exploit)["content"])["status"] == "FAILED"


def test_single_expert_conversion_remains_available(tmp_path: Path):
    source = _write_jsonl(tmp_path / "accepted.jsonl", [_accepted("recon-1")])
    output = tmp_path / "recon.jsonl"

    result = convert_feedback(source, tmp_path / "runs", output)

    assert result["expert"] == "recon"
    assert _trace(output)["metadata"]["phase"] == 2
    assert _save_arguments(_trace(output))["filename"] == "02_recon.md"


def test_mixed_feedback_requires_output_directory_or_filter(tmp_path: Path):
    source = _write_jsonl(
        tmp_path / "accepted.jsonl",
        [
            _accepted("recon-1"),
            _accepted(
                "secretary-1",
                expert="secretary",
                phase=6,
                target={"filename": "06_report.md", "content": "# Report"},
            ),
        ],
    )

    with pytest.raises(FeedbackConversionError, match="Mixed expert feedback"):
        convert_feedback(source, tmp_path / "runs", tmp_path / "mixed.jsonl")


def test_rejects_expert_phase_and_filename_mismatches(tmp_path: Path):
    invalid_phase = _accepted("bad-phase", expert="recon", phase=4)
    source = _write_jsonl(tmp_path / "phase.jsonl", [invalid_phase])
    with pytest.raises(FeedbackConversionError, match="cannot be routed"):
        convert_feedback_by_expert(source, tmp_path / "runs", tmp_path / "out")

    invalid_filename = _accepted(
        "bad-file",
        target={"filename": "03_recon.md", "content": "wrong prefix"},
    )
    source = _write_jsonl(tmp_path / "filename.jsonl", [invalid_filename])
    with pytest.raises(FeedbackConversionError, match="does not match phase"):
        convert_feedback_by_expert(source, tmp_path / "runs", tmp_path / "out")


def test_false_positive_without_canonical_finding_produces_empty_target(tmp_path: Path):
    run = tmp_path / "runs" / "run-1"
    run.mkdir(parents=True)
    (run / "03_vuln_analysis.json").write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {
                        "id": "F1",
                        "device_id": "camera",
                        "device_ip": "10.0.0.5",
                        "type": "rce",
                        "severity": "CRITICAL",
                        "evidence": "unsupported",
                    }
                ]
            }
        )
    )
    candidate = {
        "candidate_id": "lf-false-positive",
        "task": "finding_correction",
        "scenario_id": "1",
        "error_type": "false_positive",
        "input": {"predicted_finding": {"id": "F1"}},
        "target": {"expected_finding": None},
        "occurrences": [{"run_id": "run-1"}],
        "review": {"status": "accepted", "notes": "unsupported claim"},
    }
    source = _write_jsonl(tmp_path / "accepted.jsonl", [candidate])
    output = tmp_path / "vuln.jsonl"

    convert_feedback(source, tmp_path / "runs", output)

    payload = json.loads(_save_arguments(_trace(output))["content"])
    assert payload["vulnerabilities"] == []
    assert payload["summary"]["total"] == 0
