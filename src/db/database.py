"""SQLite schema and helpers for LANCE.

stdlib ``sqlite3`` only — no ORM, no new dependency. The database is a single
file (``data/lance.db`` by default, overridable via the ``LANCE_DB_PATH`` env
var for tests). Everything is best-effort: writes are wrapped so a DB failure
logs a warning and lets the caller continue (the pipeline must never crash
because persistence hiccuped).

Tables
------
providers     : LLM providers (name, base_url, api_key_env, default_model, kind)
models        : curated models shown in the dashboard / usable by the agent
runs          : one row per pipeline run (upserted on run_dir)
run_scores    : benchmark scores for a run (precision/recall/f1/weighted/MHR…)
phase_usage   : per-phase token/cost/duration breakdown for a run
"""
from __future__ import annotations

import logging
import os
import sqlite3
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Repo root = .../src/db/database.py -> parents[2]
_ROOT = Path(__file__).resolve().parents[2]
DB_PATH = _ROOT / "data" / "lance.db"


def _db_path() -> Path:
    """Resolve the DB path (env override wins — used by tests)."""
    override = os.environ.get("LANCE_DB_PATH")
    return Path(override) if override else DB_PATH


_SCHEMA = """
CREATE TABLE IF NOT EXISTS providers (
    name           TEXT PRIMARY KEY,
    base_url       TEXT,
    api_key_env    TEXT,
    default_model  TEXT,
    kind           TEXT NOT NULL DEFAULT 'cloud'   -- 'cloud' | 'local'
);

CREATE TABLE IF NOT EXISTS models (
    slug            TEXT PRIMARY KEY,
    label           TEXT,
    provider        TEXT REFERENCES providers(name),
    recommended     INTEGER NOT NULL DEFAULT 0,
    enabled         INTEGER NOT NULL DEFAULT 1,
    input_per_mtok  REAL,
    output_per_mtok REAL,
    base_url        TEXT,                          -- per-model override (local endpoints)
    subscription    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_dir     TEXT UNIQUE,
    ts          TEXT,
    scenario_id TEXT,
    model       TEXT,
    provider    TEXT,
    status      TEXT,
    cost_usd    REAL,
    tokens_in   INTEGER,
    tokens_out  INTEGER,
    git_commit  TEXT
);

CREATE TABLE IF NOT EXISTS run_scores (
    run_id                INTEGER REFERENCES runs(id) ON DELETE CASCADE,
    scenario_id           TEXT,
    precision             REAL,
    recall                REAL,
    f1                    REAL,
    weighted              REAL,
    exploitation_coverage REAL,
    mhr_1                 REAL,
    mhr_2                 REAL,
    mhr_3                 REAL,
    tp                    INTEGER,
    fp                    INTEGER,
    fn                    INTEGER,
    PRIMARY KEY (run_id)
);

CREATE TABLE IF NOT EXISTS phase_usage (
    run_id      INTEGER REFERENCES runs(id) ON DELETE CASCADE,
    phase       INTEGER,
    agent       TEXT,
    tokens_in   INTEGER,
    tokens_out  INTEGER,
    tool_calls  INTEGER,
    turns       INTEGER,
    duration_s  REAL,
    cost_usd    REAL
);
"""


def get_conn() -> sqlite3.Connection:
    """Open a connection to the LANCE DB (creates the parent dir if needed)."""
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    """Create all tables if absent. Idempotent."""
    with get_conn() as conn:
        conn.executescript(_SCHEMA)


# ── Providers / models ───────────────────────────────────────────────────────

def upsert_provider(
    name: str,
    base_url: str | None = None,
    api_key_env: str | None = None,
    default_model: str | None = None,
    kind: str = "cloud",
) -> None:
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO providers (name, base_url, api_key_env, default_model, kind)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                base_url      = excluded.base_url,
                api_key_env   = excluded.api_key_env,
                default_model = excluded.default_model,
                kind          = excluded.kind
            """,
            (name, base_url, api_key_env, default_model, kind),
        )


def upsert_model(
    slug: str,
    label: str | None = None,
    provider: str | None = None,
    recommended: bool = False,
    enabled: bool = True,
    input_per_mtok: float | None = None,
    output_per_mtok: float | None = None,
    base_url: str | None = None,
    subscription: bool = False,
) -> None:
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO models
                (slug, label, provider, recommended, enabled,
                 input_per_mtok, output_per_mtok, base_url, subscription)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(slug) DO UPDATE SET
                label           = excluded.label,
                provider        = excluded.provider,
                recommended     = excluded.recommended,
                enabled         = excluded.enabled,
                input_per_mtok  = excluded.input_per_mtok,
                output_per_mtok = excluded.output_per_mtok,
                base_url        = excluded.base_url,
                subscription    = excluded.subscription
            """,
            (slug, label, provider, int(recommended), int(enabled),
             input_per_mtok, output_per_mtok, base_url, int(subscription)),
        )


def list_models(enabled_only: bool = True) -> list[dict[str, Any]]:
    """Return models joined to their provider (base_url falls back to provider)."""
    sql = """
        SELECT m.slug, m.label, m.provider, m.recommended, m.enabled,
               m.input_per_mtok, m.output_per_mtok,
               COALESCE(m.base_url, p.base_url) AS base_url,
               m.subscription, p.kind AS provider_kind
        FROM models m
        LEFT JOIN providers p ON p.name = m.provider
    """
    if enabled_only:
        sql += " WHERE m.enabled = 1"
    sql += " ORDER BY m.recommended DESC, m.slug"
    try:
        with get_conn() as conn:
            return [dict(r) for r in conn.execute(sql).fetchall()]
    except sqlite3.Error as exc:
        log.warning("list_models failed: %s", exc)
        return []


def get_provider(name: str) -> dict[str, Any] | None:
    """Return a provider row as a dict, or None if absent / DB unavailable."""
    try:
        with get_conn() as conn:
            row = conn.execute(
                "SELECT name, base_url, api_key_env, default_model, kind "
                "FROM providers WHERE name = ?",
                (name,),
            ).fetchone()
            return dict(row) if row else None
    except sqlite3.Error as exc:
        log.warning("get_provider(%s) failed: %s", name, exc)
        return None


# ── Runs / scores / usage ────────────────────────────────────────────────────

def record_run(meta: dict[str, Any]) -> int | None:
    """Upsert a run keyed on ``run_dir``; return its row id (or None on failure).

    Recognised keys: run_dir, ts, scenario_id, model, provider, status,
    cost_usd, tokens_in, tokens_out, git_commit.
    """
    run_dir = meta.get("run_dir")
    if not run_dir:
        log.warning("record_run: missing run_dir, skipping")
        return None
    try:
        with get_conn() as conn:
            conn.execute(
                """
                INSERT INTO runs
                    (run_dir, ts, scenario_id, model, provider, status,
                     cost_usd, tokens_in, tokens_out, git_commit)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_dir) DO UPDATE SET
                    ts          = excluded.ts,
                    scenario_id = excluded.scenario_id,
                    model       = excluded.model,
                    provider    = excluded.provider,
                    status      = excluded.status,
                    cost_usd    = excluded.cost_usd,
                    tokens_in   = excluded.tokens_in,
                    tokens_out  = excluded.tokens_out,
                    git_commit  = excluded.git_commit
                """,
                (
                    str(run_dir),
                    meta.get("ts"),
                    _as_text(meta.get("scenario_id")),
                    meta.get("model"),
                    meta.get("provider"),
                    meta.get("status"),
                    meta.get("cost_usd"),
                    meta.get("tokens_in"),
                    meta.get("tokens_out"),
                    meta.get("git_commit"),
                ),
            )
            row = conn.execute(
                "SELECT id FROM runs WHERE run_dir = ?", (str(run_dir),)
            ).fetchone()
            return int(row["id"]) if row else None
    except sqlite3.Error as exc:
        log.warning("record_run failed: %s", exc)
        return None


def record_scores(run_id: int, scenario_id: Any = None, **scores: Any) -> None:
    """Insert/replace benchmark scores for a run.

    Accepted keys: precision, recall, f1, weighted, exploitation_coverage,
    mhr_1, mhr_2, mhr_3, tp, fp, fn.
    """
    if run_id is None:
        return
    try:
        with get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO run_scores
                    (run_id, scenario_id, precision, recall, f1, weighted,
                     exploitation_coverage, mhr_1, mhr_2, mhr_3, tp, fp, fn)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    _as_text(scenario_id),
                    scores.get("precision"),
                    scores.get("recall"),
                    scores.get("f1"),
                    scores.get("weighted"),
                    scores.get("exploitation_coverage"),
                    scores.get("mhr_1"),
                    scores.get("mhr_2"),
                    scores.get("mhr_3"),
                    scores.get("tp"),
                    scores.get("fp"),
                    scores.get("fn"),
                ),
            )
    except sqlite3.Error as exc:
        log.warning("record_scores failed: %s", exc)


def record_phase_usage(run_id: int, phases: list[dict[str, Any]]) -> None:
    """Replace the per-phase usage rows for a run.

    Each phase dict may use either the cost-summary keys (agent, turns,
    input_tokens, output_tokens, tool_calls, cost_usd, duration_s) or the
    normalised DB keys (tokens_in/tokens_out). ``phase`` is the 1-based index
    unless explicitly provided.
    """
    if run_id is None or not phases:
        return
    try:
        with get_conn() as conn:
            conn.execute("DELETE FROM phase_usage WHERE run_id = ?", (run_id,))
            for i, p in enumerate(phases, start=1):
                conn.execute(
                    """
                    INSERT INTO phase_usage
                        (run_id, phase, agent, tokens_in, tokens_out,
                         tool_calls, turns, duration_s, cost_usd)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        p.get("phase", i),
                        p.get("agent"),
                        p.get("tokens_in", p.get("input_tokens")),
                        p.get("tokens_out", p.get("output_tokens")),
                        p.get("tool_calls"),
                        p.get("turns"),
                        p.get("duration_s"),
                        p.get("cost_usd"),
                    ),
                )
    except sqlite3.Error as exc:
        log.warning("record_phase_usage failed: %s", exc)


def _as_text(value: Any) -> str | None:
    """Normalise scenario ids etc. to text (so '1' and 1 don't split rows)."""
    return None if value is None else str(value)
