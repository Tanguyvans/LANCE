"""Comparison contracts and bounded, public records. No laboratory execution."""
import asyncio
import json
import threading
from types import SimpleNamespace

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError
import pytest

from src.api.routes import comparisons, pipeline
from src.benchmark import policy_pair_runner as pairs

BODY = {"runner_kind": "comparison", "scenario_id": "1", "provider": "minimax", "model": "test"}
ID = "2026-10-15_150000_0123456789ab"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(pairs, "OUTPUT", tmp_path)
    app = FastAPI()
    app.include_router(comparisons.router, prefix="/api/comparisons")
    return TestClient(app)


def test_comparison_requires_fixed_common_contract():
    request = pipeline.StartRequest(**BODY)
    assert request.max_tool_calls == 200 and request.max_duration_s == 600 and request.max_cost_usd == 2
    assert request.execution_profile == "full" and request.comparison_order == "rules-first"


@pytest.mark.parametrize("patch", [
    {"scenario_id": None}, {"model": " "}, {"provider": None}, {"auto_teardown": False},
    {"phases": [1, 3, 4]}, {"target_network": "192.0.2.0/24"}, {"execution_profile": "compact"},
    {"architecture": "flat"}, {"blind": True}, {"max_tool_calls": 2001}, {"max_duration_s": float("nan")},
    {"max_cost_usd": 0}, {"max_cost_usd": float("inf")}, {"arbitrary_command": "anything"},
    {"audit_inventory": {"vulnerabilities": []}},
])
def test_mixed_or_unbounded_comparison_contracts_are_rejected(patch):
    with pytest.raises(ValidationError):
        pipeline.StartRequest(**(BODY | patch))


def test_unavailable_runtime_cannot_start_or_write_artifacts(monkeypatch):
    monkeypatch.setattr(pairs, "runtime_readiness", lambda: {"available": False, "reason": "nato unavailable"})
    monkeypatch.setattr(pairs, "PairRunner", lambda *args, **kwargs: pytest.fail("Must not create a pair"))
    with pytest.raises(HTTPException) as exc:
        asyncio.run(pipeline.start_pipeline(pipeline.StartRequest(**BODY)))
    assert exc.value.status_code == 503


def test_comparison_uses_same_single_run_coordinator_and_exposes_reload_id(monkeypatch):
    from src.api.routes import models
    snapshot = dict(pipeline._state)
    monkeypatch.setattr(pairs, "runtime_readiness", lambda: {"available": True})
    monkeypatch.setattr(models, "list_models", lambda: {"models": [{"id": "test", "provider": "minimax", "available": True}]})
    monkeypatch.setattr(pairs, "PairRunner", lambda config: SimpleNamespace(id=ID, config=config))
    monkeypatch.setattr(pipeline.threading, "Thread", lambda **kwargs: SimpleNamespace(start=lambda: None))
    pipeline._state.update(running=False, teardown_running=False)
    try:
        response = asyncio.run(pipeline.start_pipeline(pipeline.StartRequest(**BODY)))
        assert response["comparison_id"] == ID
        assert pipeline.get_status()["runner_kind"] == "comparison"
        assert pipeline.get_status()["comparison_id"] == ID
        with pytest.raises(HTTPException) as exc:
            asyncio.run(pipeline.start_pipeline(pipeline.StartRequest(**BODY)))
        assert exc.value.status_code == 409
    finally:
        pipeline._state.clear()
        pipeline._state.update(snapshot)


def _record(root, identifier=ID):
    directory = root / identifier
    directory.mkdir()
    value = {"schema_version": 1, "id": identifier, "status": "failed", "started_at": "2026-10-15T12:00:00Z",
             "scenario": {"id": "1", "name": "Public"}, "config": {"model": "test"}, "comparison": None}
    (directory / "pair.json").write_text(json.dumps(value))
    return directory, value


def test_public_history_pagination_and_download_preserve_failed_attempt(client, tmp_path):
    _record(tmp_path)
    _record(tmp_path, "2026-10-15_150001_0123456789ab")
    page = client.get("/api/comparisons?limit=1&offset=1").json()
    assert page["total"] == 2 and page["items"][0]["id"] == ID
    assert page["items"][0]["comparable"] is None
    assert client.get(f"/api/comparisons/{ID}").json()["status"] == "failed"
    assert client.get(f"/api/comparisons/{ID}/download").headers["content-disposition"].startswith("attachment;")


@pytest.mark.parametrize("query", ["offset=-1", "limit=0", "limit=51"])
def test_pagination_is_bounded(client, query):
    assert client.get("/api/comparisons?" + query).status_code == 422


def test_symlink_and_oversized_records_are_rejected(client, tmp_path):
    directory, _ = _record(tmp_path)
    path = directory / "pair.json"
    path.unlink()
    path.symlink_to(tmp_path / "outside.json")
    assert client.get(f"/api/comparisons/{ID}").status_code == 404
    path.unlink()
    path.write_bytes(b" " * (comparisons.MAX_RECORD_BYTES + 1))
    assert client.get(f"/api/comparisons/{ID}").status_code == 413
    assert client.get("/api/comparisons").json()["total"] == 0


def test_invalid_and_nonpublic_metadata_fail_closed(client, tmp_path, monkeypatch):
    directory, value = _record(tmp_path)
    monkeypatch.setattr(pairs, "public_spec", lambda sid: (_ for _ in ()).throw(ValueError("not public")))
    assert client.get(f"/api/comparisons/{ID}").status_code == 422
    assert client.get("/api/comparisons").json()["items"] == []


def test_interrupted_record_is_not_shown_as_still_running(client, tmp_path, monkeypatch):
    directory, value = _record(tmp_path)
    value["status"] = "running"
    (directory / "pair.json").write_text(json.dumps(value))
    monkeypatch.setattr(pipeline, "get_status", lambda: {"running": False})
    data = client.get(f"/api/comparisons/{ID}").json()
    assert data["status"] == "incomplete" and data["interrupted"] is True


def test_nonfinite_record_values_are_not_json_responses(client, tmp_path):
    directory, _ = _record(tmp_path)
    (directory / "pair.json").write_text('{"cost":1e999}')
    assert client.get(f"/api/comparisons/{ID}").status_code == 422


def test_terminal_callback_publishes_idle_before_worker_returns_and_cannot_finish_next_run():
    snapshot = dict(pipeline._state)
    pipeline._state.update(running=True, comparison_id=ID, stop_event=threading.Event(),
                           queue=None, loop=None, recent_events=[])
    def run(callback, stop_event):
        callback({"type": "comparison_done", "status": "completed"})
        assert pipeline._state["running"] is False
        # Simulate a new operation accepted immediately after completion.
        pipeline._state.update(running=True, comparison_id="next-operation")
    try:
        pipeline._comparison_thread(SimpleNamespace(id=ID, run=run))
        assert pipeline._state["running"] is True
        assert pipeline._state["comparison_id"] == "next-operation"
    finally:
        pipeline._state.clear()
        pipeline._state.update(snapshot)
