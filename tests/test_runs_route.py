"""Tests for src/api/routes/runs.py helper functions."""
import json
from uuid import uuid4

import pytest
from fastapi import HTTPException

from src.api.routes import runs
from src.api.routes.runs import (
    _extract_commit,
    _load_sealed_summary,
    _resolve_run_dir,
    _visible_files,
    download_run,
    get_benchmark,
    get_run,
    get_run_file,
    list_runs,
    score_run,
)


class TestExtractCommit:
    def test_reads_from_run_meta(self, tmp_path):
        (tmp_path / "run_meta.json").write_text(json.dumps({"git_commit": "abc1234", "model": "gpt-4"}))
        assert _extract_commit(tmp_path) == "abc1234"

    def test_reads_from_scenario_meta_fallback(self, tmp_path):
        (tmp_path / "scenario_meta.json").write_text(json.dumps({
            "scenario_id": 1, "git_commit": "deadbeef", "model": "claude",
        }))
        assert _extract_commit(tmp_path) == "deadbeef"

    def test_run_meta_takes_priority(self, tmp_path):
        (tmp_path / "run_meta.json").write_text(json.dumps({"git_commit": "aaa1111"}))
        (tmp_path / "scenario_meta.json").write_text(json.dumps({"git_commit": "bbb2222"}))
        assert _extract_commit(tmp_path) == "aaa1111"

    def test_returns_none_when_no_commit(self, tmp_path):
        (tmp_path / "run_meta.json").write_text(json.dumps({"model": "gpt-4"}))
        assert _extract_commit(tmp_path) is None

    def test_returns_none_when_no_files(self, tmp_path):
        assert _extract_commit(tmp_path) is None

    def test_returns_none_on_corrupt_json(self, tmp_path):
        (tmp_path / "run_meta.json").write_text("not json")
        assert _extract_commit(tmp_path) is None


def _sealed_summary(scenario_id="24", benchmark_version="3.1.0"):
    return {
        "schema_version": "1",
        "submission_id": str(uuid4()),
        "scenario_id": scenario_id,
        "benchmark_version": benchmark_version,
        "status": "complete",
        "score_visibility": "aggregate",
        "metrics": {"overall_score": 0.875},
        "signature": "controller-signature",
    }


class TestRunVisibility:
    def test_public_listing_hides_ground_truth_and_symlinks(self, tmp_path):
        (tmp_path / "scenario_meta.json").write_text(json.dumps({"scenario_id": "1"}))
        (tmp_path / "ground_truth.yaml").write_text("secret")
        (tmp_path / "report.md").write_text("ok")
        (tmp_path / "alias.md").symlink_to(tmp_path / "ground_truth.yaml")

        assert _visible_files(tmp_path) == ["report.md", "scenario_meta.json"]

    def test_sealed_listing_exposes_no_raw_artifacts(self, tmp_path):
        (tmp_path / "scenario_meta.json").write_text(
            json.dumps({"scenario_id": "24", "split": "eval-sealed"})
        )
        (tmp_path / "03_vuln_analysis.json").write_text("{}")

        assert _visible_files(tmp_path) == []

    def test_corrupt_scenario_marker_fails_closed(self, tmp_path):
        (tmp_path / "scenario_meta.json").write_text("not-json")
        (tmp_path / "report.md").write_text("raw")

        assert _visible_files(tmp_path) == []

    def test_sealed_run_meta_still_restricts_files_without_scenario_meta(self, tmp_path):
        (tmp_path / "run_meta.json").write_text(
            json.dumps({"benchmark_split": "eval-sealed"})
        )
        (tmp_path / "report.md").write_text("raw")

        assert _visible_files(tmp_path) == []


class TestSealedSummaryTrustBoundary:
    def test_run_local_summary_is_ignored(self, tmp_path, monkeypatch):
        run_dir = tmp_path / "run-1"
        run_dir.mkdir()
        (run_dir / "evaluation_summary.json").write_text(json.dumps(_sealed_summary()))
        monkeypatch.delenv("SEALED_EVALUATION_DIR", raising=False)

        assert _load_sealed_summary(run_dir, "24") is None

    def test_trusted_summary_is_validated_and_signature_not_exposed(self, tmp_path, monkeypatch):
        run_dir = tmp_path / "run-1"
        trusted_dir = tmp_path / "trusted"
        run_dir.mkdir()
        trusted_dir.mkdir()
        (trusted_dir / "run-1.json").write_text(json.dumps(_sealed_summary()))
        monkeypatch.setenv("SEALED_EVALUATION_DIR", str(trusted_dir))

        summary = _load_sealed_summary(run_dir, "24")

        assert summary["metrics"] == {"overall_score": 0.875}
        assert "signature" not in summary

    def test_trusted_summary_rejects_wrong_benchmark_version(self, tmp_path, monkeypatch):
        run_dir = tmp_path / "run-1"
        trusted_dir = tmp_path / "trusted"
        run_dir.mkdir()
        trusted_dir.mkdir()
        (trusted_dir / "run-1.json").write_text(
            json.dumps(_sealed_summary(benchmark_version="old"))
        )
        monkeypatch.setenv("SEALED_EVALUATION_DIR", str(trusted_dir))

        with pytest.raises(ValueError, match="benchmark version mismatch"):
            _load_sealed_summary(run_dir, "24")


class TestRunEndpoints:
    def test_run_id_cannot_escape_output_directory(self, tmp_path, monkeypatch):
        monkeypatch.setattr(runs, "OUTPUT_DIR", tmp_path)

        with pytest.raises(HTTPException) as exc:
            _resolve_run_dir("../outside")

        assert exc.value.status_code == 400

    def test_sealed_files_and_zip_are_denied(self, tmp_path, monkeypatch):
        output_dir = tmp_path / "output"
        run_dir = output_dir / "sealed-run"
        run_dir.mkdir(parents=True)
        (run_dir / "scenario_meta.json").write_text(
            json.dumps({"scenario_id": "24", "split": "eval-sealed"})
        )
        (run_dir / "03_vuln_analysis.json").write_text("{}")
        (run_dir / "cost_summary.json").write_text(json.dumps({"total_cost_usd": 999.0}))
        monkeypatch.setattr(runs, "OUTPUT_DIR", output_dir)

        with pytest.raises(HTTPException) as file_exc:
            get_run_file("sealed-run", "03_vuln_analysis.json")
        with pytest.raises(HTTPException) as zip_exc:
            download_run("sealed-run")

        assert file_exc.value.status_code == 403
        assert zip_exc.value.status_code == 403

    def test_sealed_run_is_explicitly_marked_in_list_and_detail(self, tmp_path, monkeypatch):
        run_dir = tmp_path / "sealed-run"
        run_dir.mkdir()
        (run_dir / "scenario_meta.json").write_text(
            json.dumps({"scenario_id": "24", "split": "eval-sealed"})
        )
        (run_dir / "03_vuln_analysis.json").write_text("{}")
        (run_dir / "cost_summary.json").write_text(json.dumps({"total_cost_usd": 999.0}))
        monkeypatch.setattr(runs, "OUTPUT_DIR", tmp_path)

        listed = list_runs()
        detail = get_run("sealed-run")

        assert listed[0]["sealed"] is True
        assert listed[0]["files"] == []
        assert listed[0]["cost"] is None
        assert detail["sealed"] is True
        assert detail["files"] == []
        assert detail["cost"] is None

    def test_sealed_benchmark_row_is_marked_and_aggregate_only(self, tmp_path, monkeypatch):
        output_dir = tmp_path / "output"
        run_dir = output_dir / "sealed-run"
        trusted_dir = tmp_path / "trusted"
        run_dir.mkdir(parents=True)
        trusted_dir.mkdir()
        (run_dir / "scenario_meta.json").write_text(
            json.dumps({"scenario_id": "24", "split": "eval-sealed"})
        )
        (run_dir / "03_vuln_analysis.json").write_text("{}")
        (run_dir / "cost_summary.json").write_text(json.dumps({"total_cost_usd": 999.0}))
        summary = _sealed_summary()
        summary["metrics"]["cost_usd"] = 1.25
        (trusted_dir / "sealed-run.json").write_text(json.dumps(summary))
        monkeypatch.setattr(runs, "OUTPUT_DIR", output_dir)
        monkeypatch.setenv("SEALED_EVALUATION_DIR", str(trusted_dir))

        row = get_benchmark()[0]

        assert row["sealed"] is True
        assert row["cost"] is None
        assert row["score"]["metrics"] == {"overall_score": 0.875, "cost_usd": 1.25}
        assert "signature" not in row["score"]

    def test_forged_local_sealed_score_is_not_returned(self, tmp_path, monkeypatch):
        output_dir = tmp_path / "output"
        run_dir = output_dir / "sealed-run"
        run_dir.mkdir(parents=True)
        (run_dir / "scenario_meta.json").write_text(
            json.dumps({"scenario_id": "24", "split": "eval-sealed"})
        )
        (run_dir / "evaluation_summary.json").write_text(json.dumps(_sealed_summary()))
        monkeypatch.setattr(runs, "OUTPUT_DIR", output_dir)
        monkeypatch.delenv("SEALED_EVALUATION_DIR", raising=False)

        with pytest.raises(HTTPException) as exc:
            score_run("sealed-run")

        assert exc.value.status_code == 404

    def test_public_hardened_variant_can_be_scored(self, tmp_path, monkeypatch):
        output_dir = tmp_path / "output"
        run_dir = output_dir / "public-run"
        run_dir.mkdir(parents=True)
        (run_dir / "scenario_meta.json").write_text(
            json.dumps({"scenario_id": "1h", "split": "dev-public"})
        )
        (run_dir / "03_vuln_analysis.json").write_text(
            json.dumps({"vulnerabilities": []})
        )
        monkeypatch.setattr(runs, "OUTPUT_DIR", output_dir)

        result = score_run("public-run")

        assert result["scenario_id"] == "1h"
        assert result["is_zero_gt"] is True
        assert result["scenario_score_pct"] == 100.0

    def test_benchmark_row_exposes_evaluation_failure(self, tmp_path, monkeypatch):
        run_dir = tmp_path / "public-run"
        run_dir.mkdir()
        (run_dir / "scenario_meta.json").write_text(json.dumps({
            "scenario_id": "1",
            "split": "dev-public",
        }))
        (run_dir / "03_vuln_analysis.json").write_text(
            json.dumps({"vulnerabilities": []})
        )
        ground_truth = tmp_path / "ground_truth.yaml"
        ground_truth.write_text("scenario_id: '1'\nvulnerabilities: []\n")
        monkeypatch.setattr(runs, "OUTPUT_DIR", tmp_path)
        monkeypatch.setattr(runs, "resolve_ground_truth_path", lambda _: ground_truth)

        import src.benchmark.evaluator as evaluator
        monkeypatch.setattr(
            evaluator,
            "evaluate",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(NameError("broken helper")),
        )

        row = get_benchmark()[0]

        assert row["score"] is None
        assert row["score_error"] == "Evaluation failed: broken helper"
