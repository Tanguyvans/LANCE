"""Shared harness core: one run lifecycle, and an incomplete run is refused.

The governance boundary reads a fixed attribute set through ``getattr`` with
defaults, so an omission surfaces only when a tool call misbehaves. The core
exists to make that omission loud instead.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from benchmarks.experiments.harness import build_run, new_run
from benchmarks.experiments.harness import run as core
from src.agent.core.executor import check_execution_limits


def _args(**changes):
    base = dict(max_tool_calls=8, max_duration_s=None, max_turns=12, max_cost_usd=None,
                model="qwen3.8:27b", provider="ollama-umons")
    base.update(changes)
    return SimpleNamespace(**base)


def test_build_run_exposes_the_governance_surface(tmp_path):
    run = build_run(directory=tmp_path / "run", scope="test-scope", phase="test-phase",
                    policy="rules", args=_args())
    for name in core.REQUIRED_ATTRIBUTES:
        assert hasattr(run, name), name
    assert run.context["target_subnet"] == "127.0.0.1/32"
    assert run.decision_policy == "rules"
    assert run.experiment_scope == "test-scope"


def test_build_run_opens_an_empty_ledger(tmp_path):
    run = build_run(directory=tmp_path / "run", scope="s", phase="p", policy="rules", args=_args())
    assert (run.run_dir / "tool_calls.jsonl").is_file()
    assert (run.run_dir / "tool_calls.jsonl").read_text() == ""


def test_a_deterministic_arm_never_claims_a_model(tmp_path):
    run = build_run(directory=tmp_path / "run", scope="s", phase="p", policy="rules",
                    args=_args(model="qwen3.8:27b", provider="ollama-umons"))
    assert run.tracker.model == ""
    assert run.tracker.provider == ""


def test_an_llm_arm_records_its_model(tmp_path):
    run = build_run(directory=tmp_path / "run", scope="s", phase="p", policy="llm",
                    args=_args())
    assert run.tracker.model == "qwen3.8:27b"
    assert run.tracker.provider == "ollama-umons"


def test_the_run_satisfies_the_execution_limits(tmp_path):
    """The governance boundary must accept the run as it is (no limit hit)."""
    run = build_run(directory=tmp_path / "run", scope="s", phase="p", policy="rules", args=_args())
    check_execution_limits(run)


def test_a_call_budget_is_enforced_by_the_tool_boundary(tmp_path):
    """max_tool_calls is checked in wrap_tool, not in check_execution_limits."""
    from src.agent.core.executor import wrap_tool

    run = build_run(directory=tmp_path / "run", scope="s", phase="p", policy="rules",
                    args=_args(max_tool_calls=1))
    run._tool_call_count = 1
    tool = {"name": "nmap_scan", "function": lambda **kwargs: "{}"}
    wrapped = wrap_tool(run, tool)
    with pytest.raises(Exception, match="Tool-call budget"):
        wrapped["function"](target="127.0.0.1")


def test_a_missing_attribute_is_refused(tmp_path, monkeypatch):
    """A partial run must fail at build time, not during a tool call."""
    monkeypatch.setattr(core, "REQUIRED_ATTRIBUTES",
                        core.REQUIRED_ATTRIBUTES + ("attribute_that_does_not_exist",))
    with pytest.raises(RuntimeError, match="attribute_that_does_not_exist"):
        build_run(directory=tmp_path / "run", scope="s", phase="p", policy="rules", args=_args())


def test_a_missing_context_key_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "REQUIRED_CONTEXT_KEYS", ("target_subnet", "absent_key"))
    with pytest.raises(RuntimeError, match="absent_key"):
        build_run(directory=tmp_path / "run", scope="s", phase="p", policy="rules", args=_args())


def test_new_run_keeps_the_positional_call_sites(tmp_path):
    run = new_run(tmp_path / "run", "rules", _args(), scope="mqtt-reference-calibration")
    assert run.experiment_scope == "mqtt-reference-calibration"


def test_require_attributes_rejects_a_foreign_object():
    with pytest.raises(RuntimeError, match="missing"):
        core.require_attributes(SimpleNamespace(run_dir=None))
