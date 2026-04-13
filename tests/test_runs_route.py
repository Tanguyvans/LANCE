"""Tests for src/api/routes/runs.py helper functions."""
import json
from pathlib import Path

import pytest

from src.api.routes.runs import _extract_commit


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
