"""SQLite persistence for LANCE — runs, scores, phase usage, models and providers.

Lightweight stdlib-only layer (no ORM). The DB lives at ``data/lance.db`` and is
optional: every write is best-effort and never raises into the pipeline. See
``src.db.database`` for the schema and helpers, ``src.db.seed`` to populate it.
"""
from __future__ import annotations

from src.db.database import (  # noqa: F401
    DB_PATH,
    get_conn,
    get_provider,
    init_db,
    list_models,
    record_phase_usage,
    record_run,
    record_scores,
    upsert_model,
    upsert_provider,
)
