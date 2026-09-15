"""Backend-only tests for the evidence-backed Phase 5 observation projection."""
from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from src.agent.phases.intrusion.observations import project_intrusion_observations
from src.agent.phases.intrusion.run import IntrusionPhase
from src.api.routes import runs
from src.benchmark.metric_contract import EVIDENCE_CONTRACT_VERSION


def _model(*, accesses: int = 0, chains: int = 0, transitions: int = 0) -> dict:
    return {
        "summary": {},
        "credential_pool": [],
        "compromised_devices": [{} for _ in range(accesses)],
        "chains": [
            {"hops": [{} for _ in range(transitions + 1)]}
            for _ in range(chains)
        ],
    }


def _record(
    ip: str = "192.0.2.10",
    *,
    ref: str = "tc-" + "0" * 32,
    phase: int | str = 5,
    tool: str = "ssh_exec",
    service: str | None = None,
    result: dict | None = None,
    origin: str = "runner",
    args: dict | None = None,
) -> dict:
    record_args = args or {
        "ip": ip,
        "user": "root",
        "password": "not-used-by-projection",
        "command": "id",
    }
    if service is not None:
        record_args["service"] = service
    return {
        "phase": phase,
        "tool": tool,
        "args": record_args,
        "result": result or {
            "success": True,
            "return_code": 0,
            "stdout": "uid=0(root) gid=0(root)",
        },
        "execution_origin": origin,
        "evidence_ref": ref,
    }


def _run(
    tmp_path: Path,
    *,
    model: dict | str | None = None,
    records: list[dict] | str | None = None,
    meta: dict | str | None = None,
) -> Path:
    if meta is None:
        meta = {
            "evidence_contract_version": EVIDENCE_CONTRACT_VERSION,
            "evidence_integrity": True,
        }
    (tmp_path / "run_meta.json").write_text(
        meta if isinstance(meta, str) else json.dumps(meta), encoding="utf-8"
    )
    if model is not None:
        (tmp_path / "05_intrusion.json").write_text(
            model if isinstance(model, str) else json.dumps(model), encoding="utf-8"
        )
    if records is not None:
        if isinstance(records, str):
            content = records
        else:
            content = "\n".join(json.dumps(record) for record in records) + "\n"
        (tmp_path / "tool_calls.jsonl").write_text(content, encoding="utf-8")
    return tmp_path


def test_model_declarations_do_not_create_accesses_without_ledger(tmp_path):
    projection = project_intrusion_observations(
        _run(tmp_path, model=_model(accesses=2, chains=1, transitions=1))
    )

    assert projection == {
        "schema_version": "intrusion-observations-v1",
        "available": False,
        "reason": "tool_calls.jsonl is missing or not a regular file",
        "accesses": [],
        "transitions": [],
        "transition_evidence_available": False,
        "declarations": {"accesses": 2, "chains": 1, "transitions": 1},
    }


def test_executor_ssh_record_proves_only_its_observed_ip_and_ref(tmp_path):
    projection = project_intrusion_observations(_run(
        tmp_path,
        model=_model(accesses=2, chains=1, transitions=1),
        records=[_record(ref="tc-" + "1" * 32)],
    ))

    assert projection["available"] is True
    assert projection["accesses"] == [{
        "device_ip": "192.0.2.10",
        "evidence_refs": ["tc-" + "1" * 32],
    }]
    assert projection["transitions"] == []
    assert projection["transition_evidence_available"] is False
    assert projection["declarations"] == {"accesses": 2, "chains": 1, "transitions": 1}


@pytest.mark.parametrize("model", [None, "not-json"])
def test_missing_or_corrupt_model_does_not_hide_real_ledger_access(tmp_path, model):
    projection = project_intrusion_observations(_run(
        tmp_path,
        model=model,
        records=[_record(ref="tc-" + "2" * 32)],
    ))

    assert projection["available"] is True
    assert projection["accesses"] == [{
        "device_ip": "192.0.2.10",
        "evidence_refs": ["tc-" + "2" * 32],
    }]
    assert projection["declarations"] is None


def test_try_credential_uses_shared_access_supported_semantics_including_http(tmp_path):
    projection = project_intrusion_observations(_run(
        tmp_path,
        model=_model(),
        records=[_record(
            tool="try_credential",
            service="http",
            ref="tc-" + "3" * 32,
            result={
                "success": True,
                "authenticated": True,
                "service": "http",
                "http_code": 200,
                "unauthenticated_http_code": 401,
            },
        )],
    ))

    assert projection["accesses"] == [{
        "device_ip": "192.0.2.10",
        "evidence_refs": ["tc-" + "3" * 32],
    }]


def test_duplicate_executor_references_are_ambiguous(tmp_path):
    ref = "tc-" + "4" * 32
    projection = project_intrusion_observations(_run(
        tmp_path,
        model=_model(),
        records=[_record("192.0.2.10", ref=ref), _record("192.0.2.11", ref=ref)],
    ))

    assert projection["available"] is False
    assert projection["accesses"] == []
    assert projection["reason"] == "duplicate evidence reference is ambiguous"


def test_duplicate_reference_is_checked_before_success_verdict(tmp_path):
    ref = "tc-" + "5" * 32
    projection = project_intrusion_observations(_run(
        tmp_path,
        model=_model(),
        records=[
            _record("192.0.2.10", ref=ref),
            _record(
                "192.0.2.11",
                ref=ref,
                result={"success": False, "authenticated": False, "return_code": 1},
            ),
        ],
    ))

    assert projection["available"] is False
    assert projection["accesses"] == []
    assert projection["reason"] == "duplicate evidence reference is ambiguous"


def test_duplicate_reference_in_phase4_invalidates_phase5_corroboration(tmp_path):
    ref = "tc-" + "6" * 32
    projection = project_intrusion_observations(_run(
        tmp_path,
        model=_model(),
        records=[_record(ref=ref), _record(phase=4, ref=ref)],
    ))

    assert projection["available"] is False
    assert projection["accesses"] == []


def test_model_forged_evidence_fields_are_ignored(tmp_path):
    model = _model(accesses=1, chains=1, transitions=1)
    model["compromised_devices"][0] = {
        "device_ip": "192.0.2.99",
        "evidence_status": "verified",
        "evidence_refs": ["forged-secret-ref"],
    }
    projection = project_intrusion_observations(_run(
        tmp_path, model=model, records=[]
    ))

    assert projection["available"] is True
    assert projection["accesses"] == []
    assert "forged-secret-ref" not in json.dumps(projection)


def test_two_direct_accesses_are_not_a_transition(tmp_path):
    projection = project_intrusion_observations(_run(
        tmp_path,
        model=_model(accesses=2),
        records=[
            _record("192.0.2.10", ref="tc-" + "a" * 32),
            _record("192.0.2.11", ref="tc-" + "b" * 32),
        ],
    ))

    assert projection["accesses"] == [
        {"device_ip": "192.0.2.10", "evidence_refs": ["tc-" + "a" * 32]},
        {"device_ip": "192.0.2.11", "evidence_refs": ["tc-" + "b" * 32]},
    ]
    assert projection["transitions"] == []


@pytest.mark.parametrize("record", [
    _record(args={"ip": "not-an-ip", "command": "id"}),
    _record(tool="try_credential", service="http"),
    _record(tool="http_get", args={"url": "http://192.0.2.10/"}),
    _record(phase=4),
    _record(args={"target": "192.0.2.10 192.0.2.11", "command": "id"}),
    _record(origin="model"),
    _record(result={"success": False, "return_code": 1, "stdout": ""}),
])
def test_non_access_records_do_not_create_observations(tmp_path, record):
    projection = project_intrusion_observations(_run(
        tmp_path, model=_model(), records=[record]
    ))

    assert projection["available"] is True
    assert projection["accesses"] == []


@pytest.mark.parametrize("field_value", [
    {},
    {"evidence_contract_version": "evidence-v1"},
    {"evidence_contract_version": EVIDENCE_CONTRACT_VERSION, "evidence_integrity": False},
    {"evidence_contract_version": EVIDENCE_CONTRACT_VERSION, "integrity": False},
    {"evidence_contract_version": EVIDENCE_CONTRACT_VERSION, "evidence_contract_compatible": False},
])
def test_metadata_failure_is_unavailable_and_has_no_accesses(tmp_path, field_value):
    projection = project_intrusion_observations(_run(
        tmp_path, model=_model(), records=[_record()], meta=field_value
    ))

    assert projection["available"] is False
    assert projection["accesses"] == []
    assert projection["reason"]


@pytest.mark.parametrize("bad_journal", ["{broken\n", "[]\n"])
def test_corrupt_or_non_object_journal_is_unavailable(tmp_path, bad_journal):
    projection = project_intrusion_observations(_run(
        tmp_path, model=_model(accesses=1), records=bad_journal
    ))

    assert projection["available"] is False
    assert projection["accesses"] == []
    assert projection["declarations"]["accesses"] == 1


def test_projection_does_not_modify_run_files(tmp_path):
    run_dir = _run(tmp_path, model=_model(), records=[_record()])
    before = {
        path.name: path.read_bytes()
        for path in run_dir.iterdir()
        if path.is_file()
    }

    project_intrusion_observations(run_dir)

    assert before == {
        path.name: path.read_bytes()
        for path in run_dir.iterdir()
        if path.is_file()
    }


def test_sse_projection_is_independent_of_campaign_status_and_done_is_explicit(tmp_path):
    run_dir = _run(tmp_path, model=_model(), records=[_record()])
    phase = SimpleNamespace(run_dir=run_dir, _phase5_terminal_status="failed:incomplete")
    events: list[dict] = []

    IntrusionPhase._emit_intrusion_events(phase, events.append)

    observation = next(event for event in events if event["type"] == "intrusion_observations")
    assert observation["available"] is True
    assert observation["accesses"]
    assert any(event["type"] == "warn" for event in events)
    assert not any(event["type"] == "intrusion_done" for event in events)
    assert not any(event["type"] in {"intrusion_compromised", "intrusion_hop"} for event in events)

    phase._phase5_terminal_status = "completed"
    events.clear()
    IntrusionPhase._emit_intrusion_events(phase, events.append)
    done = next(event for event in events if event["type"] == "intrusion_done")
    assert done == {"type": "intrusion_done", "devices_compromised": 1, "hops": 0}

    phase._evidence_integrity_failed = True
    events.clear()
    IntrusionPhase._emit_intrusion_events(phase, events.append)
    assert next(event for event in events if event["type"] == "intrusion_observations")["available"] is False
    assert not any(event["type"] == "intrusion_done" for event in events)


def test_symlink_and_fifo_guards_fail_closed(tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"secret": "do-not-read"}), encoding="utf-8")
    (tmp_path / "05_intrusion.json").symlink_to(outside)
    projection = project_intrusion_observations(
        _run(tmp_path, model=None, records=[])
    )
    assert projection["available"] is True
    assert projection["declarations"] is None

    (tmp_path / "05_intrusion.json").unlink()
    (tmp_path / "05_intrusion.json").write_text(json.dumps(_model()), encoding="utf-8")
    fifo = tmp_path / "tool_calls.jsonl"
    fifo.unlink()
    os.mkfifo(fifo)
    projection = project_intrusion_observations(tmp_path)
    assert projection["available"] is False


def test_sealed_api_endpoint_is_denied_and_public_endpoint_returns_shape(tmp_path, monkeypatch):
    run_dir = tmp_path / "run-1"
    run_dir.mkdir()
    _run(run_dir, model=_model(), records=[])
    monkeypatch.setattr(runs, "OUTPUT_DIR", tmp_path)

    response = runs.get_intrusion_observations("run-1")
    assert list(response) == [
        "schema_version", "available", "reason", "accesses",
        "transitions", "transition_evidence_available", "declarations",
    ]

    (run_dir / "scenario_meta.json").write_text(
        json.dumps({"scenario_id": "20", "split": "eval-sealed"}), encoding="utf-8"
    )
    with pytest.raises(HTTPException) as exc:
        runs.get_intrusion_observations("run-1")
    assert exc.value.status_code == 403
