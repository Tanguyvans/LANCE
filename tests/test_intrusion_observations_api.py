"""HTTP routing and privacy boundaries of the observation projection."""
import json

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from src.api.routes import runs
from src.benchmark.metric_contract import EVIDENCE_CONTRACT_VERSION


@pytest.fixture
def api(tmp_path, monkeypatch):
    run = tmp_path / "run-1"
    run.mkdir()
    (run / "run_meta.json").write_text(json.dumps({
        "evidence_contract_version": EVIDENCE_CONTRACT_VERSION,
        "evidence_integrity": True,
    }))
    (run / "tool_calls.jsonl").write_text(json.dumps({
        "phase": 5, "execution_origin": "runner", "tool": "ssh_exec",
        "evidence_ref": "tc-" + "b" * 32,
        "args": {"ip": "192.0.2.1", "user": "test", "password": "secret-canary", "command": "id"},
        "result": {"return_code": 0, "stdout": "uid=1000(test)"},
    }) + "\n")
    monkeypatch.setattr(runs, "OUTPUT_DIR", tmp_path)
    app = FastAPI()
    app.include_router(runs.router, prefix="/api/runs")
    with TestClient(app) as client:
        yield client, run


def test_computed_route_wins_over_an_agent_named_artifact_without_writing(api):
    client, run = api
    (run / "intrusion-observations").write_text('{"forged":true}')
    before = {p.name: p.read_bytes() for p in run.iterdir()}
    response = client.get("/api/runs/run-1/intrusion-observations")
    assert response.status_code == 200
    data = response.json()
    assert data["schema_version"] == "intrusion-observations-v1"
    assert data["accesses"][0]["device_ip"] == "192.0.2.1"
    assert data["declarations"] is None  # model output isn't required for an access
    assert "secret-canary" not in response.text and "forged" not in response.text
    assert {p.name: p.read_bytes() for p in run.iterdir()} == before


def test_sealed_run_cannot_expose_individual_access_observations(api):
    client, run = api
    meta = json.loads((run / "run_meta.json").read_text())
    meta["benchmark_split"] = "eval-sealed"
    (run / "run_meta.json").write_text(json.dumps(meta))
    assert client.get("/api/runs/run-1/intrusion-observations").status_code == 403


def test_journal_symlink_cannot_supply_accesses(api):
    client, run = api
    journal = run / "tool_calls.jsonl"
    other = run.parent / "outside-ledger.jsonl"
    journal.rename(other)
    journal.symlink_to(other)
    response = client.get("/api/runs/run-1/intrusion-observations")
    assert response.status_code == 200
    assert response.json()["available"] is False
    assert response.json()["accesses"] == []


def test_metadata_symlink_is_private_not_a_proof_contract(api):
    client, run = api
    metadata = run / "run_meta.json"
    other = run.parent / "outside-meta.json"
    metadata.rename(other)
    metadata.symlink_to(other)
    assert client.get("/api/runs/run-1/intrusion-observations").status_code == 403
