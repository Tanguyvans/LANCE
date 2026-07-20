from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from src.learning.error_mining import (
    LearningLoopError,
    export_accepted,
    mine_runs,
    review_candidate,
    validate_dataset,
)


def _write_gt(path: Path) -> Path:
    path.mkdir()
    gt = {
        "scenario_id": "1",
        "vulnerabilities": [
            {
                "id": "V1",
                "title": "MQTT sans authentification",
                "device": "mqtt",
                "ip": "10.0.0.10",
                "severity": "high",
                "category": "misconfiguration",
            },
            {
                "id": "V2",
                "title": "Directory listing",
                "device": "web",
                "ip": "10.0.0.20",
                "severity": "medium",
                "category": "misconfiguration",
            },
        ],
        "scoring": {
            "weights": {"critical": 4, "high": 3, "medium": 2, "low": 1},
            "max_weighted_score": 5,
        },
        "bonus_types": [],
        "attack_paths": [],
    }
    gt_file = path / "scenario_1.yaml"
    gt_file.write_text(yaml.safe_dump(gt), encoding="utf-8")
    return gt_file


def _write_run(root: Path, name: str = "run-1", *, split: str = "dev-public") -> Path:
    run = root / name
    run.mkdir(parents=True)
    (run / "scenario_meta.json").write_text(json.dumps({
        "scenario_id": "1",
        "split": split,
        "model": "test-model",
        "git_commit": "abc123",
    }), encoding="utf-8")
    (run / "run_meta.json").write_text(json.dumps({
        "benchmark_split": split,
        "model": "test-model",
    }), encoding="utf-8")
    (run / "03_vuln_analysis.json").write_text(json.dumps({
        "vulnerabilities": [
            {
                "id": "F1",
                "device_ip": "10.0.0.10",
                "type": "no_auth",
                "severity": "low",
                "details": "Anonymous MQTT access was confirmed.",
                "evidence": "connected without credentials",
                "cve_ids": [],
            },
            {
                "id": "F2",
                "device_ip": "10.0.0.99",
                "type": "rce",
                "severity": "critical",
                "details": "Unsupported remote code execution claim.",
                "evidence": "",
                "cve_ids": [],
            },
        ]
    }), encoding="utf-8")
    return run


def _records(dataset: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in (dataset / "candidates.jsonl").read_text(encoding="utf-8").splitlines()
        if line
    ]


def test_mines_false_negative_false_positive_and_severity_error(tmp_path: Path):
    runs = tmp_path / "runs"
    runs.mkdir()
    _write_run(runs)
    gt_dir = tmp_path / "gt"
    _write_gt(gt_dir)
    dataset = tmp_path / "dataset"

    manifest = mine_runs(runs, dataset, ground_truth_dir=gt_dir)

    assert manifest["candidate_count"] == 3
    records = _records(dataset)
    assert {item["error_type"] for item in records} == {
        "false_negative", "false_positive", "severity_mismatch",
    }
    false_positive = next(item for item in records if item["error_type"] == "false_positive")
    assert false_positive["input"]["predicted_finding"]["details"] == (
        "Unsupported remote code execution claim."
    )
    assert validate_dataset(dataset)["valid"] is True


def test_sealed_run_is_skipped_and_never_mined(tmp_path: Path):
    runs = tmp_path / "runs"
    runs.mkdir()
    run = _write_run(runs, split="eval-sealed")
    meta = json.loads((run / "scenario_meta.json").read_text())
    meta["scenario_id"] = "20"
    (run / "scenario_meta.json").write_text(json.dumps(meta))
    gt_dir = tmp_path / "gt"
    _write_gt(gt_dir)

    manifest = mine_runs(runs, tmp_path / "dataset", ground_truth_dir=gt_dir)

    assert manifest["candidate_count"] == 0
    assert manifest["processed_runs"] == []
    assert "sealed" in manifest["skipped_runs"][0]["reason"].lower()


def test_export_contains_accepted_candidates_only(tmp_path: Path):
    runs = tmp_path / "runs"
    runs.mkdir()
    _write_run(runs)
    gt_dir = tmp_path / "gt"
    _write_gt(gt_dir)
    dataset = tmp_path / "dataset"
    mine_runs(runs, dataset, ground_truth_dir=gt_dir)
    records = _records(dataset)

    review_candidate(
        dataset,
        records[0]["candidate_id"],
        status="accepted",
        reviewer="test",
        notes="verified",
    )
    destination = tmp_path / "export"
    manifest = export_accepted(dataset, destination)

    assert manifest["candidate_count"] == 1
    exported = [
        json.loads(line)
        for line in (destination / "accepted_candidates.jsonl").read_text().splitlines()
    ]
    assert exported[0]["review"]["status"] == "accepted"


def test_export_refuses_dataset_without_accepted_candidate(tmp_path: Path):
    runs = tmp_path / "runs"
    runs.mkdir()
    _write_run(runs)
    gt_dir = tmp_path / "gt"
    _write_gt(gt_dir)
    dataset = tmp_path / "dataset"
    mine_runs(runs, dataset, ground_truth_dir=gt_dir)

    with pytest.raises(LearningLoopError, match="No accepted"):
        export_accepted(dataset, tmp_path / "export")


def test_routes_causal_feedback_to_recon_exploit_and_secretary(tmp_path: Path):
    runs = tmp_path / "runs"
    runs.mkdir()
    run = _write_run(runs)
    gt_dir = tmp_path / "gt"
    gt_file = _write_gt(gt_dir)
    gt = yaml.safe_load(gt_file.read_text())
    gt["topology"] = {
        "router": {"name": "router", "ip": "10.0.0.1", "type": "router"},
        "services": [
            {"name": "mqtt", "ip": "10.0.0.10", "role": "mqtt_broker"},
            {"name": "web", "ip": "10.0.0.20", "role": "web_server"},
        ],
    }
    gt["vulnerabilities"][0]["role"] = "mqtt_broker"
    gt["vulnerabilities"][0]["indicators"] = ["Port 1883/tcp"]
    gt["vulnerabilities"][1]["role"] = "web_server"
    gt["vulnerabilities"][1]["indicators"] = ["Port 80/tcp"]
    gt_file.write_text(yaml.safe_dump(gt))

    (run / "01_graph_analysis.md").write_text(
        "# Graph\n\n## 1. Summary\n\nrouter 10.0.0.1 and mqtt 10.0.0.10\n"
        "\n## 2. Scan Plan\n\nScan declared targets.\n"
    )
    (run / "02_recon.md").write_text(
        "# Recon\n\n## 1. Summary\n\nMQTT target covered.\n\n"
        "## 2. Discovered Services per Device\n\n"
        "| Device | IP | Ports |\n|---|---|---|\n| mqtt | 10.0.0.10 | 1883 |\n\n"
        "## 3. Key Findings\n\nNo web target was scanned.\n"
    )
    (run / "04_exploitation.json").write_text(json.dumps({
        "tests": [
            {
                "vuln_id": "F1",
                "device_id": "mqtt",
                "device_ip": "10.0.0.10",
                "vuln_type": "no_auth",
                "severity": "low",
                "status": "CONFIRMED",
                "evidence": "anonymous subscribe accepted; topic payload received",
                "evidence_level": 2,
                "tool_used": "mqtt_listen",
                "data_extracted": ["message"],
            },
            {
                "vuln_id": "F2",
                "device_id": "other",
                "device_ip": "10.0.0.99",
                "vuln_type": "rce",
                "severity": "critical",
                "status": "CONFIRMED",
                "evidence": "RCE was not confirmed by the tool",
                "evidence_level": 1,
                "tool_used": "",
                "data_extracted": [],
            },
        ]
    }))
    (run / "06_report.md").write_text("# Draft report\n\nThe draft propagates evaluation errors.\n")

    dataset = tmp_path / "dataset"
    manifest = mine_runs(runs, dataset, ground_truth_dir=gt_dir)
    records = _records(dataset)

    assert manifest["counts_by_expert"]["recon"] == 1
    assert manifest["counts_by_expert"]["exploit"] == 1
    assert manifest["counts_by_expert"]["secretary"] == 2
    assert any(item["task"] == "finding_correction" for item in records)
    recon = next(item for item in records if item["task"] == "recon_correction")
    assert recon["evaluation"]["attributed_false_negatives"] == ["V2"]
    assert not any(
        item["task"] == "finding_correction"
        and item["error_type"] == "false_negative"
        and item["evaluation"].get("gt_id") == "V2"
        for item in records
    )
    exploit = next(item for item in records if item["task"] == "exploit_correction")
    assert exploit["target"]["expected_deliverable"]["content"]["status"] == "FAILED"
    assert {item["phase"] for item in records if item.get("expert") == "secretary"} == {1, 6}
    assert validate_dataset(dataset)["valid"] is True


def test_invalid_exploit_status_is_mined_even_without_benchmark_false_positive(tmp_path: Path):
    runs = tmp_path / "runs"
    runs.mkdir()
    run = _write_run(runs)
    (run / "04_exploitation.json").write_text(json.dumps({
        "tests": [{
            "vuln_id": "F1",
            "device_id": "mqtt",
            "device_ip": "10.0.0.10",
            "vuln_type": "no_auth",
            "severity": "low",
            "status": "SAVE_SUCCESS",
            "evidence": "",
            "evidence_level": 1,
        }]
    }))
    gt_dir = tmp_path / "gt"
    _write_gt(gt_dir)

    dataset = tmp_path / "dataset"
    mine_runs(runs, dataset, ground_truth_dir=gt_dir)

    invalid = next(
        item for item in _records(dataset)
        if item["error_type"] == "invalid_exploit_status"
    )
    assert invalid["expert"] == "exploit"
    assert invalid["target"]["expected_deliverable"]["content"]["status"] == "FAILED"


def test_discovers_nested_run_groups_and_preserves_relative_run_id(tmp_path: Path):
    runs = tmp_path / "runs"
    nested_root = runs / "model-family"
    nested_root.mkdir(parents=True)
    _write_run(nested_root, name="scenario-run")
    gt_dir = tmp_path / "gt"
    _write_gt(gt_dir)

    dataset = tmp_path / "dataset"
    manifest = mine_runs(runs, dataset, ground_truth_dir=gt_dir)

    assert manifest["processed_runs"] == ["model-family/scenario-run"]
    records = _records(dataset)
    assert all(
        item["occurrences"][0]["run_id"] == "model-family/scenario-run"
        for item in records
    )
