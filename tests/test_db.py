"""Tests for the SQLite persistence layer (src.db.database)."""
from __future__ import annotations

import importlib

import pytest


@pytest.fixture()
def db(tmp_path, monkeypatch):
    """Fresh DB at a temp path (LANCE_DB_PATH override) with schema created."""
    monkeypatch.setenv("LANCE_DB_PATH", str(tmp_path / "test.db"))
    database = importlib.import_module("src.db.database")
    database.init_db()
    return database


def test_init_db_idempotent(db):
    # Calling init_db twice must not raise and tables must exist.
    db.init_db()
    db.init_db()
    with db.get_conn() as conn:
        names = {r["name"] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
    assert {"providers", "models", "runs", "run_scores", "phase_usage"} <= names


def test_upsert_and_get_provider(db):
    db.upsert_provider("local", base_url="http://x/v1", api_key_env="LOCAL_API_KEY", kind="local")
    row = db.get_provider("local")
    assert row is not None
    assert row["base_url"] == "http://x/v1"
    assert row["kind"] == "local"

    # Upsert overwrites in place (no duplicate row).
    db.upsert_provider("local", base_url="http://y/v1", api_key_env="LOCAL_API_KEY", kind="local")
    assert db.get_provider("local")["base_url"] == "http://y/v1"
    with db.get_conn() as conn:
        assert conn.execute("SELECT COUNT(*) FROM providers").fetchone()[0] == 1


def test_upsert_model_and_list(db):
    db.upsert_provider("openrouter", base_url="https://openrouter.ai/api/v1",
                       api_key_env="OPENROUTER_API_KEY")
    db.upsert_model("deepseek/deepseek-v4-flash", label="deepseek-v4-flash",
                    provider="openrouter", recommended=True)
    db.upsert_model("hidden/model", label="hidden", provider="openrouter", enabled=False)

    enabled = db.list_models(enabled_only=True)
    slugs = [m["slug"] for m in enabled]
    assert "deepseek/deepseek-v4-flash" in slugs
    assert "hidden/model" not in slugs
    # base_url falls back to the provider's base_url via the join.
    flash = next(m for m in enabled if m["slug"] == "deepseek/deepseek-v4-flash")
    assert flash["base_url"] == "https://openrouter.ai/api/v1"
    assert flash["recommended"] == 1

    assert len(db.list_models(enabled_only=False)) == 2


def test_record_run_upsert_and_read(db):
    meta = {
        "run_dir": "output/agent/2026-01-01_000000",
        "ts": "2026-01-01_000000",
        "scenario_id": 1,
        "model": "deepseek/deepseek-v4-flash",
        "provider": "openrouter",
        "status": "completed",
        "cost_usd": 0.12,
        "tokens_in": 1000,
        "tokens_out": 200,
        "git_commit": "abc1234",
    }
    run_id = db.record_run(meta)
    assert run_id is not None

    # Same run_dir upserts to the same id (no duplicate run row).
    meta["cost_usd"] = 0.34
    assert db.record_run(meta) == run_id
    with db.get_conn() as conn:
        rows = conn.execute("SELECT cost_usd, scenario_id FROM runs").fetchall()
    assert len(rows) == 1
    assert rows[0]["cost_usd"] == 0.34
    assert rows[0]["scenario_id"] == "1"  # normalised to text


def test_record_scores_and_phase_usage(db):
    run_id = db.record_run({"run_dir": "output/agent/run-x", "scenario_id": "2"})
    db.record_scores(run_id, scenario_id="2", precision=0.9, recall=0.8, f1=0.85,
                     weighted=42.0, exploitation_coverage=0.5, tp=8, fp=1, fn=2)
    db.record_phase_usage(run_id, [
        {"agent": "recon", "input_tokens": 500, "output_tokens": 100,
         "tool_calls": 3, "turns": 4, "duration_s": 12.0, "cost_usd": 0.01},
    ])
    with db.get_conn() as conn:
        s = conn.execute("SELECT * FROM run_scores WHERE run_id=?", (run_id,)).fetchone()
        p = conn.execute("SELECT * FROM phase_usage WHERE run_id=?", (run_id,)).fetchall()
    assert s["precision"] == 0.9 and s["tp"] == 8
    assert len(p) == 1
    assert p[0]["tokens_in"] == 500 and p[0]["phase"] == 1
