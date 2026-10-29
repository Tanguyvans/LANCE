"""Hermetic sandbox: deterministic arms run outside the laboratory.

The sandbox proves the harness runs without a broker, a model or the lab. It
must also refuse anything that would break that promise, and it must never
claim a measurement: no LLM arm, no preflight, no admission.
"""
from __future__ import annotations

import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from benchmarks.experiments import sandbox


def test_sandbox_runs_every_frozen_fixture(tmp_path):
    report = sandbox.run_sandbox(tmp_path)
    assert report["hermetic"] is True
    assert report["breaches"] == []
    assert len(report["trials"]) == 8
    assert {trial["view"] for trial in report["trials"]} == {"raw", "normalized"}
    assert {trial["schema"] for trial in report["trials"]} == {"reference", "variant"}


def test_sandbox_writes_the_trial_artifacts(tmp_path):
    sandbox.run_sandbox(tmp_path)
    for name in ("dossier.json", "oracle.json", "answer.json", "journal.jsonl", "evaluation.json"):
        assert (tmp_path / "trial-00" / name).is_file(), name
    assert (tmp_path / "sandbox-report.json").is_file()


def test_sandbox_never_claims_a_measurement(tmp_path):
    report = sandbox.run_sandbox(tmp_path)
    assert report["claims_measurement"] is False
    text = json.dumps(report)
    assert "pair_admissible" not in text.replace("Never yields pair_admissible", "")
    assert "mt_admissible" not in text.replace("mt_admissible.", "")


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
