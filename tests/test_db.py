"""Tests for the SQLite persistence layer (src.db.database)."""
from __future__ import annotations

import importlib
import sqlite3

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


def test_init_db_migrates_legacy_model_table(tmp_path, monkeypatch):
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE models (slug TEXT PRIMARY KEY)")
    monkeypatch.setenv("LANCE_DB_PATH", str(path))

    from src.db import database

    database.init_db()
    with database.get_conn() as conn:
        columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(models)")
        }

    assert {
        "parameter_count_b", "active_parameter_count_b", "profile_policy"
    } <= columns


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


def test_model_parameter_metadata_round_trip(db):
    db.upsert_provider("local", kind="local")
    db.upsert_model(
        "moe/model",
        provider="local",
        parameter_count_b=30,
        active_parameter_count_b=3,
        profile_policy="auto",
    )

    row = db.get_model("moe/model")
    assert row["parameter_count_b"] == 30
    assert row["active_parameter_count_b"] == 3
    assert row["profile_policy"] == "auto"


def test_model_api_and_auto_profile_resolution(db):
    from fastapi import HTTPException
    from src.agent.execution_profiles import resolve_execution_profile_for_model
    from src.api.routes.models import ModelCreate, ModelPatch, create_model, update_model

    db.upsert_provider("local", kind="local")
    created = create_model(ModelCreate(
        slug="moe/api-model",
        provider="local",
        parameter_count_b=30,
        active_parameter_count_b=3,
    ))
    resolution = resolve_execution_profile_for_model("auto", "moe/api-model")

    assert created["active_parameter_count_b"] == 3
    assert created["effective_profile"] == "compact"
    assert resolution.profile.name == "compact"
    assert resolution.resolution_basis == "active_parameters"

    updated = update_model("moe/api-model", ModelPatch(profile_policy="full"))
    assert updated["profile_policy"] == "full"
    assert updated["effective_profile"] == "full"
    assert resolve_execution_profile_for_model(
        "auto", "moe/api-model"
    ).profile.name == "full"

    with pytest.raises(HTTPException) as exc:
        create_model(ModelCreate(
            slug="invalid/moe",
            provider="local",
            parameter_count_b=3,
            active_parameter_count_b=4,
        ))
    assert exc.value.status_code == 422


def test_public_model_api_migrates_legacy_db_and_keeps_moe_router(
    tmp_path, monkeypatch
):
    path = tmp_path / "legacy-model-api.db"
    with sqlite3.connect(path) as conn:
        conn.execute(
            "CREATE TABLE providers ("
            "name TEXT PRIMARY KEY, base_url TEXT, api_key_env TEXT, "
            "default_model TEXT, kind TEXT NOT NULL DEFAULT 'cloud')"
        )
        conn.execute(
            "CREATE TABLE models ("
            "slug TEXT PRIMARY KEY, label TEXT, provider TEXT, "
            "recommended INTEGER NOT NULL DEFAULT 0, "
            "enabled INTEGER NOT NULL DEFAULT 1, input_per_mtok REAL, "
            "output_per_mtok REAL, base_url TEXT, "
            "subscription INTEGER NOT NULL DEFAULT 0)"
        )
        conn.execute(
            "INSERT INTO providers VALUES (?, ?, ?, ?, ?)",
            ("local-moe", "http://moe.test/v1", "LOCAL_API_KEY", "lance-moe", "local"),
        )
        conn.execute(
            "INSERT INTO models (slug, label, provider, recommended, enabled) "
            "VALUES (?, ?, ?, ?, ?)",
            ("lance-moe", "LANCE HMoE (Auto-Router)", "local-moe", 1, 1),
        )

    monkeypatch.setenv("LANCE_DB_PATH", str(path))
    from src.api.routes import models

    monkeypatch.setattr(models, "_load_pricing", lambda: {})
    monkeypatch.setattr(models, "_load_openrouter_catalog", lambda **_kwargs: [])
    monkeypatch.setattr(models, "get_codex_catalog", lambda **_kwargs: {
        "available": False, "account_type": None, "plan_type": None,
        "models": [], "error": "not logged in", "auth_command": "codex login",
    })
    response = models.list_models()

    router = next(model for model in response["models"] if model["id"] == "lance-moe")
    assert router["provider"] == "local-moe"
    assert router["available"] is True

    with sqlite3.connect(path) as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(models)")}
    assert {
        "parameter_count_b", "active_parameter_count_b", "profile_policy"
    } <= columns


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
