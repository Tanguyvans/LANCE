"""SSH V2 software calibration: real executor/SSH adapter, simulated process I/O."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tarfile
import threading
import time
from types import SimpleNamespace

import pytest

from src.agent.audit_experiment import digest
from src.agent.core.executor import EvidenceWriteError
from src.agent.tools import recon_tools
from benchmarks.experiments.ssh_reference import (
    CONTRACT, IDENTITY_MARKER, OBJECT_MARKER, bind_ssh_tool, evaluate_trial, proof_command,
    run_rules, validate_briefing,
)


@pytest.fixture
def briefing():
    return {
        "schema_version": 1, "scenario_id": "s_ssh_identifiants", "instance_id": "development-01",
        "target_network": "192.0.2.0/24",
        "target": {"asset_id": "edge", "ip": "192.0.2.17", "port": 2222},
        "dictionary": [{"user": "admin", "password": "admin"}, {"user": "iot", "password": "test"}],
        "control_credential": {"user": "auditor", "password": "development-control-only"},
        "proof_path": "/var/lib/lance/private-object.txt",
    }


def oracle_for(briefing, positive, payload="fresh-development-object\n"):
    return {"schema_version": 1, "briefing_sha256": digest(briefing),
            "intentional_flaws": int(positive), "canary_sha256": hashlib.sha256(payload.encode()).hexdigest()}


def ledger(run):
    path = run.run_dir / "tool_calls.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.is_file() else []


def execution(tmp_path, monkeypatch, *, positive, max_calls=10, failure=None):
    calls = []

    def process(argv, timeout):
        calls.append(argv)
        user = argv[-2].split("@", 1)[0]
        if user != "auditor" and failure == "exception":
            raise TimeoutError("simulated process failure")
        if user != "auditor" and failure == "timeout":
            return {"return_code": -1, "stdout": "", "stderr": "Connection timed out", "error_kind": "timeout"}
        if user == "auditor" or positive and user == "iot" and argv[2] == "test":
            return {"return_code": 0, "stdout": f"{IDENTITY_MARKER}\n{user}\n{OBJECT_MARKER}\nfresh-development-object\n", "stderr": ""}
        return {"return_code": 255, "stdout": "", "stderr": f"{user}@192.0.2.17: Permission denied (password)."}

    monkeypatch.setattr(recon_tools, "_run", process)
    tmp_path.mkdir(parents=True, exist_ok=True)
    run = SimpleNamespace(
        run_dir=tmp_path, max_tool_calls=max_calls, max_duration_s=30,
        _artifact_log_lock=threading.Lock(), _tool_call_count=0, _run_started=time.monotonic(),
        _execution_limit_reason=None, experiment_scope="analysis-verification",
        context={"target_subnet": "192.0.2.0/24"}, decision_policy="rules",
    )
    tool = bind_ssh_tool(run)
    return run, tool, calls


@pytest.mark.parametrize("positive", [False, True], ids=["protected", "vulnerable"])
def test_rules_with_real_executor_and_ssh_adapter(tmp_path, monkeypatch, briefing, positive):
    run, tool, calls = execution(tmp_path, monkeypatch, positive=positive)
    decision = run_rules(briefing, tool)
    records = ledger(run)
    result = evaluate_trial(briefing, oracle_for(briefing, positive), records, decision)
    assert result["success"] is True
    assert result["fixture_type"] == f"s_ssh_identifiants_t0{int(positive) + 1}"
    assert result["control_proven"] and not result["false_positive"]
    assert result["mt_admissible"] is False
    assert result["measurement_status"] == "evidence_only_not_admitted"
    assert decision["finding"] is positive
    assert len(calls) == run._tool_call_count == len(records) == 3
    assert decision["evidence_refs"] == [r["evidence_ref"] for r in records]
    assert len(set(decision["evidence_refs"])) == 3
    assert all(r["execution_origin"] == "runner" and r["decision_source"] == "rules" for r in records)
    assert all(c[-3] == "-p2222" and c[-1] == proof_command(briefing) for c in calls)
    assert result["dictionary_rejections"] == (1 if positive else 2)


@pytest.mark.parametrize("field", ["intentional_flaws", "canary_sha256", "oracle", "winning_credential"])
def test_public_contract_rejects_private_answer_fields(briefing, field):
    briefing[field] = "private"
    with pytest.raises(ValueError):
        validate_briefing(briefing)


@pytest.mark.parametrize("change", [
    {"target": {"asset_id": "edge", "ip": "198.51.100.17", "port": 2222}},
    {"target": {"asset_id": "edge", "ip": "192.0.2.17", "port": True}},
    {"proof_path": "/var/lib/../private.txt"},
    {"proof_path": "/var/lib/proof;touch /tmp/unwanted"},
    {"schema_version": True},
])
def test_public_contract_rejects_unbound_or_malformed_inputs(briefing, change):
    briefing.update(change)
    with pytest.raises(ValueError):
        validate_briefing(briefing)


@pytest.mark.parametrize("mutation", ["host", "port", "origin", "identity", "command", "stale_object", "missing_object"])
def test_positive_requires_same_target_identity_command_and_fresh_read(tmp_path, monkeypatch, briefing, mutation):
    run, tool, _ = execution(tmp_path, monkeypatch, positive=True)
    decision = run_rules(briefing, tool)
    records = ledger(run)
    weak = records[-1]
    if mutation == "host":
        weak["args"]["ip"] = "192.0.2.18"
    elif mutation == "port":
        weak["args"]["port"] = 22
    elif mutation == "origin":
        weak["execution_origin"] = "unattested-relay"
    elif mutation == "identity":
        result = json.loads(weak["result"])
        result["stdout"] = result["stdout"].replace("\niot\n", "\nroot\n")
        weak["result"] = result
    elif mutation == "command":
        weak["args"]["command"] = "id"
    else:
        result = json.loads(weak["result"])
        result["stdout"] = result["stdout"].replace("fresh-development-object\n", "old-object\n" if mutation == "stale_object" else "")
        weak["result"] = result
    evaluated = evaluate_trial(briefing, oracle_for(briefing, True), records, decision)
    assert evaluated["success"] is False
    assert evaluated["unsupported_finding"] is True


def test_cannot_combine_identity_and_object_from_two_sessions(tmp_path, monkeypatch, briefing):
    run, tool, _ = execution(tmp_path, monkeypatch, positive=True)
    decision = run_rules(briefing, tool)
    records = ledger(run)
    separate = deepcopy(records[-1])
    separate["evidence_ref"] = "tc-another-session"
    records[-1]["result"] = {"return_code": 0, "stdout": f"{IDENTITY_MARKER}\niot\n"}
    separate["result"] = {"return_code": 0, "stdout": f"{OBJECT_MARKER}\nfresh-development-object\n"}
    records.append(separate)
    decision["evidence_refs"].append(separate["evidence_ref"])
    assert evaluate_trial(briefing, oracle_for(briefing, True), records, decision)["success"] is False


@pytest.mark.parametrize("failure", ["timeout", "exception"])
def test_transport_failures_never_certify_protected_posture(tmp_path, monkeypatch, briefing, failure):
    run, tool, _ = execution(tmp_path, monkeypatch, positive=False, failure=failure)
    decision = run_rules(briefing, tool)
    result = evaluate_trial(briefing, oracle_for(briefing, False), ledger(run), decision)
    assert result["success"] is False
    assert result["dictionary_rejections"] == 0
    assert len(ledger(run)) >= 2  # Failed operation still has raw evidence.
    if failure == "exception":
        assert decision["status"] == "failed"
        assert decision["error_type"] == "TimeoutError"


def test_budget_exhaustion_keeps_attempt_and_non_success(tmp_path, monkeypatch, briefing):
    run, tool, calls = execution(tmp_path, monkeypatch, positive=False, max_calls=1)
    decision = run_rules(briefing, tool)
    assert decision["status"] == "budget_exceeded"
    assert len(calls) == len(ledger(run)) == 1
    assert evaluate_trial(briefing, oracle_for(briefing, False), ledger(run), decision)["success"] is False


def test_successful_last_call_finishing_after_deadline_is_not_success(tmp_path, monkeypatch, briefing):
    run, tool, calls = execution(tmp_path, monkeypatch, positive=True)
    run.max_duration_s = 1
    clock = {"now": run._run_started}
    process = recon_tools._run

    def late_process(argv, timeout):
        result = process(argv, timeout)
        if argv[-2].startswith("iot@"):
            clock["now"] += 2
        return result

    monkeypatch.setattr("src.agent.core.executor.time.monotonic", lambda: clock["now"])
    monkeypatch.setattr(recon_tools, "_run", late_process)
    decision = run_rules(briefing, tool)
    assert len(calls) == len(ledger(run)) == 3
    assert json.loads(ledger(run)[-1]["result"])["success"] is True
    assert decision["status"] == "budget_exceeded"
    assert evaluate_trial(briefing, oracle_for(briefing, True), ledger(run), decision)["success"] is False


def test_archive_write_failure_propagates(tmp_path, monkeypatch, briefing):
    run, tool, _ = execution(tmp_path, monkeypatch, positive=True)
    (tmp_path / "tool_calls.jsonl").mkdir()
    with pytest.raises(EvidenceWriteError):
        run_rules(briefing, tool)
    assert run._evidence_integrity_failed


def test_unarchived_tool_is_rejected_before_execution(briefing):
    with pytest.raises(ValueError, match="common executor"):
        run_rules(briefing, lambda **kwargs: pytest.fail("Unarchived execution"))


def test_absent_collection_and_valid_empty_trial_are_distinct(briefing):
    oracle = oracle_for(briefing, False)
    decision = {"schema_version": 1, "contract": CONTRACT, "decision_policy": "rules",
                "briefing_sha256": digest(briefing), "status": "no_output", "finding": False,
                "evidence_refs": []}
    assert evaluate_trial(briefing, oracle, None, decision)["success"] is None
    assert evaluate_trial(briefing, oracle, [], None)["success"] is None
    assert evaluate_trial(briefing, oracle, [], decision)["success"] is False


def test_missing_or_duplicated_evidence_is_not_silently_accepted(tmp_path, monkeypatch, briefing):
    run, tool, _ = execution(tmp_path, monkeypatch, positive=True)
    decision = run_rules(briefing, tool)
    records = ledger(run)
    assert evaluate_trial(briefing, oracle_for(briefing, True), records[:-1], decision)["success"] is None
    with pytest.raises(ValueError, match="unique"):
        evaluate_trial(briefing, oracle_for(briefing, True), records + records[-1:], decision)


def test_private_oracle_cannot_be_reused_for_another_briefing(briefing):
    oracle = oracle_for(briefing, True)
    briefing["instance_id"] = "another-instance"
    with pytest.raises(ValueError, match="bind"):
        evaluate_trial(briefing, oracle, [], None)


def test_conflicting_protected_oracle_is_unknown(tmp_path, monkeypatch, briefing):
    run, tool, _ = execution(tmp_path, monkeypatch, positive=True)
    decision = run_rules(briefing, tool)
    evaluated = evaluate_trial(briefing, oracle_for(briefing, False), ledger(run), decision)
    assert evaluated["outcome"] == "oracle_conflict" and evaluated["success"] is None


def test_uncited_access_still_contradicts_protected_oracle(tmp_path, monkeypatch, briefing):
    run, tool, _ = execution(tmp_path, monkeypatch, positive=True)
    decision = run_rules(briefing, tool)
    decision["finding"] = False
    decision["evidence_refs"].pop()
    result = evaluate_trial(briefing, oracle_for(briefing, False), ledger(run), decision)
    assert result["outcome"] == "oracle_conflict" and result["success"] is None
    assert result["false_positive"] is None


def test_complete_existing_archive_includes_raw_hidden_and_private_pieces(tmp_path, monkeypatch, briefing):
    runs_root = tmp_path / "runs"
    run, tool, _ = execution(runs_root / "2026-10-15_120000", monkeypatch, positive=True)
    decision = run_rules(briefing, tool)
    trial = tmp_path / "trial"
    trial.mkdir()
    (trial / "rules_dir.txt").write_text(str(run.run_dir.resolve()))
    for name, value in [("briefing.json", briefing), ("oracle.json", oracle_for(briefing, True)), ("decision.json", decision)]:
        (trial / name).write_text(json.dumps(value))
    (run.run_dir / ".hidden-evidence").write_text("retain hidden files")
    support = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/benchmark/pilot_support.py"))
    archive = support["archive_trial"](trial, runs_root, tmp_path / "archive", "development-01")
    manifest = json.loads((archive.parent / "evidence-manifest.json").read_text())
    assert manifest["runs"]["llm"] is None  # No invented model run.
    with tarfile.open(archive) as bundle:
        assert "trial/oracle.json" in bundle.getnames()
        assert "trial/briefing.json" in bundle.getnames()
        assert "runs/2026-10-15_120000/.hidden-evidence" in bundle.getnames()
        for name, expected in manifest["files"].items():
            assert hashlib.sha256(bundle.extractfile(name).read()).hexdigest() == expected["sha256"]


def test_cli_assesses_archived_evidence_without_network(tmp_path, monkeypatch, briefing):
    run, tool, _ = execution(tmp_path / "run", monkeypatch, positive=False)
    decision = run_rules(briefing, tool)
    for name, value in [("briefing", briefing), ("oracle", oracle_for(briefing, False)), ("decision", decision)]:
        (tmp_path / f"{name}.json").write_text(json.dumps(value))
    command = [sys.executable, "-m", "benchmarks.experiments.ssh_reference",
               "--briefing", str(tmp_path / "briefing.json"), "--oracle", str(tmp_path / "oracle.json"),
               "--ledger", str(run.run_dir / "tool_calls.jsonl"), "--decision", str(tmp_path / "decision.json")]
    completed = subprocess.run(command, capture_output=True, text=True, check=True)
    assert json.loads(completed.stdout)["success"] is True
    (run.run_dir / "tool_calls.jsonl").unlink()
    missing = subprocess.run(command, capture_output=True, text=True)
    assert missing.returncode == 2 and json.loads(missing.stdout)["success"] is None
