from __future__ import annotations

import pytest

from src.learning.remote_runs import RemoteImportError, select_runs


def _run(
    run_id: str,
    *,
    model: str = "deepseek/deepseek-v4-flash",
    status: str = "done",
    sealed: bool = False,
) -> dict:
    return {
        "id": run_id,
        "model": model,
        "status": status,
        "sealed": sealed,
        "files": ["scenario_meta.json", "03_vuln_analysis.json"],
    }


def test_selects_only_complete_non_sealed_runs():
    selected = select_runs([
        _run("run-1"),
        _run("run-2", status="partial"),
        _run("run-3", sealed=True),
    ])
    assert [item["id"] for item in selected] == ["run-1"]


def test_model_filter_is_case_insensitive():
    selected = select_runs([
        _run("run-1"),
        _run("run-2", model="qwen2.5"),
    ], models=["DEEPSEEK-V4-FLASH"])
    assert [item["id"] for item in selected] == ["run-1"]


def test_explicit_ineligible_run_fails_closed():
    with pytest.raises(RemoteImportError, match="ineligible"):
        select_runs([_run("run-1", status="partial")], run_ids=["run-1"])
