"""Hermetic sandbox: deterministic arms run outside the laboratory.

The sandbox proves the harness runs without a broker, a model or the lab. It
must also refuse anything that would break that promise, and it must never
claim a measurement: no LLM arm, no preflight, no admission.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from benchmarks.experiments import sandbox


def test_sandbox_runs_every_frozen_fixture(tmp_path):
    report = sandbox.run_sandbox(tmp_path)
    assert report["guard_clean"] is True
    assert report["breaches"] == []
    assert len(report["trials"]) == 8
    assert {trial["view"] for trial in report["trials"]} == {"raw", "normalized"}
    assert {trial["schema"] for trial in report["trials"]} == {"reference", "variant"}


def test_sandbox_writes_the_trial_artifacts(tmp_path):
    sandbox.run_sandbox(tmp_path)
    for name in ("dossier.json", "oracle.json", "answer.json", "journal.jsonl", "evaluation.json"):
        assert (tmp_path / "trial-00" / name).is_file(), name
    assert (tmp_path / "sandbox-report.json").is_file()


def test_sandbox_never_claims_a_measurement_or_an_isolation(tmp_path):
    report = sandbox.run_sandbox(tmp_path)
    assert report["claims_measurement"] is False
    assert report["claims_isolation"] is False
    # The guard states what it observed and what it cannot see.
    assert report["guard"]["mechanism"] == "sys.addaudithook"
    assert report["guard"]["unobserved"], "the guard must state its blind spots"
    assert "not a native-code sandbox" in report["guard"]["scope"]


def test_the_arm_is_declared_not_taken_from_the_corpus(tmp_path):
    """The frozen corpus declares a dossier, never the policy under test."""
    report = sandbox.run_sandbox(tmp_path, arm="rules_attempt")
    assert report["arm"] == "rules_attempt"
    assert {trial["arm"] for trial in report["trials"]} == {"rules_attempt"}
    with pytest.raises(ValueError, match="Unknown deterministic arm"):
        sandbox.run_one(sandbox.load_corpus()["fixtures"][0], tmp_path / "x", "not_an_arm")


def test_the_convention_arm_covers_what_the_declared_parser_misses(tmp_path):
    """H2's own lesson, reproduced offline: convention beats declaration."""
    declared = sandbox.run_sandbox(tmp_path / "declared", arm="rules")
    convention = sandbox.run_sandbox(tmp_path / "convention", arm="rules_attempt")
    assert sum(t["success"] for t in declared["trials"]) < len(declared["trials"])
    assert all(t["success"] for t in convention["trials"])


def test_sandbox_reproduces_the_declared_parser_limit(tmp_path):
    """The rules arm covers declared schemas only: raw variants abstain."""
    report = sandbox.run_sandbox(tmp_path)
    raw_variants = [t for t in report["trials"] if t["view"] == "raw" and t["schema"] == "variant"]
    assert raw_variants and not any(t["success"] for t in raw_variants)
    normalized = [t for t in report["trials"] if t["view"] == "normalized"]
    assert all(t["success"] for t in normalized)


def _installed_guard(monkeypatch, allowed: Path) -> "sandbox.Guard":
    """Install a fresh process-wide guard so events actually reach it."""
    guard = sandbox.Guard(allowed, [])
    monkeypatch.setattr(sandbox, "_INSTALLED", [guard])
    sys.addaudithook(guard.__call__)
    return guard


def test_audit_hook_blocks_writes_outside_the_trial(tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    guard = _installed_guard(monkeypatch, allowed)
    with guard.active(), pytest.raises(sandbox.SandboxBreach):
        (tmp_path / "outside.txt").write_text("x", encoding="utf-8")


def test_audit_hook_allows_writes_inside_the_trial(tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    guard = _installed_guard(monkeypatch, allowed)
    target = allowed / "inside.txt"
    with guard.active():
        target.write_text("ok", encoding="utf-8")
    assert target.read_text(encoding="utf-8") == "ok"
    assert guard.breaches == []


def test_audit_hook_blocks_network_and_processes(tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    guard = _installed_guard(monkeypatch, allowed)
    with guard.active(), pytest.raises(sandbox.SandboxBreach):
        socket.create_connection(("127.0.0.1", 1), timeout=1)
    with guard.active(), pytest.raises(sandbox.SandboxBreach):
        subprocess.run(["true"], check=False)


def test_audit_hook_blocks_posix_spawn(tmp_path, monkeypatch):
    """A process can start without subprocess; an earlier guard missed this."""
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    guard = _installed_guard(monkeypatch, allowed)
    with guard.active(), pytest.raises(sandbox.SandboxBreach):
        os.posix_spawn(sys.executable, [sys.executable, "-c", "pass"], {})


def test_audit_hook_blocks_ctypes(tmp_path, monkeypatch):
    """ctypes reaches the C library without any Python process API."""
    ctypes = pytest.importorskip("ctypes")
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    guard = _installed_guard(monkeypatch, allowed)
    with guard.active(), pytest.raises(sandbox.SandboxBreach):
        ctypes.CDLL(None)


def test_guard_ignores_events_once_disarmed(tmp_path, monkeypatch):
    """The process must keep working after a sandbox run (test cleanup)."""
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    guard = _installed_guard(monkeypatch, allowed)
    with guard.active():
        pass
    (tmp_path / "cleanup.log").write_text("x", encoding="utf-8")
    assert guard.breaches == []


def test_corpus_is_the_frozen_one():
    corpus = sandbox.load_corpus()
    assert corpus["scenario_id"] == "s_mqtt_formats"
    assert len(corpus["fixtures"]) == 8


def test_install_guard_rebinds_the_scope_of_a_second_run(tmp_path, monkeypatch):
    """A second run must observe its own directory, not the first one's."""
    monkeypatch.setattr(sandbox, "_INSTALLED", [])
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    first_breaches: list[str] = []
    second_breaches: list[str] = []
    sandbox.install_guard(first, first_breaches)
    guard = sandbox.install_guard(second, second_breaches)
    assert guard.allowed == second.resolve()
    assert guard.breaches is second_breaches
    with guard.active(), pytest.raises(sandbox.SandboxBreach):
        (first / "in-first.txt").write_text("x", encoding="utf-8")
    assert first_breaches == [] and second_breaches
