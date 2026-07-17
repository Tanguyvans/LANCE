"""Tests for src/api/routes/runs.py helper functions."""
import json

import pytest
from fastapi import HTTPException

from src.api.routes import runs
from src.api.routes.runs import (
    _extract_commit,
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


class TestRunVisibility:
    def test_public_listing_hides_ground_truth_and_symlinks(self, tmp_path):
        (tmp_path / "scenario_meta.json").write_text(json.dumps({"scenario_id": "1"}))
        (tmp_path / "ground_truth.yaml").write_text("secret")
        (tmp_path / "report.md").write_text("ok")
        (tmp_path / "alias.md").symlink_to(tmp_path / "ground_truth.yaml")

        assert _visible_files(tmp_path) == ["report.md", "scenario_meta.json"]

    def test_sealed_listing_exposes_no_raw_artifacts(self, tmp_path):
        (tmp_path / "scenario_meta.json").write_text(
            json.dumps({"scenario_id": "20", "split": "eval-sealed"})
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
            json.dumps({"scenario_id": "20", "split": "eval-sealed"})
        )
        (run_dir / "03_vuln_analysis.json").write_text("{}")
        (run_dir / "cost_summary.json").write_text(json.dumps({"total_cost_usd": 999.0}))
        monkeypatch.setattr(runs, "OUTPUT_DIR", output_dir)

        with pytest.raises(HTTPException) as file_exc:
            get_run_file("sealed-run", "03_vuln_analysis.json")
        with pytest.raises(HTTPException) as zip_exc:
            download_run("sealed-run")

        assert file_exc.value.status_code == 404
        assert zip_exc.value.status_code == 404

    def test_sealed_run_is_absent_from_history_and_detail(self, tmp_path, monkeypatch):
        run_dir = tmp_path / "sealed-run"
        run_dir.mkdir()
        (run_dir / "scenario_meta.json").write_text(
            json.dumps({"scenario_id": "20", "split": "eval-sealed"})
        )
        (run_dir / "03_vuln_analysis.json").write_text("{}")
        (run_dir / "cost_summary.json").write_text(json.dumps({"total_cost_usd": 999.0}))
        monkeypatch.setattr(runs, "OUTPUT_DIR", tmp_path)

        assert list_runs() == []
        with pytest.raises(HTTPException) as exc:
            get_run("sealed-run")
        assert exc.value.status_code == 404

    def test_sealed_run_is_absent_from_benchmark(self, tmp_path, monkeypatch):
        output_dir = tmp_path / "output"
        run_dir = output_dir / "sealed-run"
        run_dir.mkdir(parents=True)
        (run_dir / "scenario_meta.json").write_text(
            json.dumps({"scenario_id": "20", "split": "eval-sealed"})
        )
        (run_dir / "03_vuln_analysis.json").write_text("{}")
        (run_dir / "cost_summary.json").write_text(json.dumps({"total_cost_usd": 999.0}))
        monkeypatch.setattr(runs, "OUTPUT_DIR", output_dir)

        assert get_benchmark() == []

    def test_forged_local_sealed_score_is_not_returned(self, tmp_path, monkeypatch):
        output_dir = tmp_path / "output"
        run_dir = output_dir / "sealed-run"
        run_dir.mkdir(parents=True)
        (run_dir / "scenario_meta.json").write_text(
            json.dumps({"scenario_id": "20", "split": "eval-sealed"})
        )
        (run_dir / "evaluation_summary.json").write_text(
            json.dumps({"metrics": {"overall_score": 1.0}, "signature": "forged"})
        )
        monkeypatch.setattr(runs, "OUTPUT_DIR", output_dir)

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
