"""SQLite-backed store for fleet orchestration history.

Single-writer model: the master VM (which owns `fleet.py`) is the only writer.
Reads happen from both the master VM (TUI History view) and any analysis tool.
WAL mode allows concurrent readers without blocking the writer.
"""
from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any


from src.baselines.paths import under_root as _under_root

DEFAULT_DB_PATH = _under_root("output", "baselines", "store.sqlite")


SCHEMA = """
CREATE TABLE IF NOT EXISTS distributed_jobs (
    distributed_job_id TEXT PRIMARY KEY,
    suite              TEXT NOT NULL,
    shard_strategy     TEXT NOT NULL,
    cases_total        INTEGER NOT NULL,
    created_at         TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT 'started',
    local_dir          TEXT,
    repo               TEXT,
    agent_command      TEXT
);

CREATE TABLE IF NOT EXISTS host_jobs (
    distributed_job_id TEXT NOT NULL,
    baseline_host      TEXT NOT NULL,
    job_id             TEXT,
    session            TEXT,
    job_dir            TEXT,
    status             TEXT NOT NULL DEFAULT 'pending',
    shard_size         INTEGER NOT NULL DEFAULT 0,
    last_payload       TEXT,
    last_seen_at       TEXT,
    error              TEXT,
    PRIMARY KEY (distributed_job_id, baseline_host),
    FOREIGN KEY (distributed_job_id) REFERENCES distributed_jobs(distributed_job_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS runs (
    run_id              INTEGER PRIMARY KEY AUTOINCREMENT,
    distributed_job_id  TEXT,
    baseline_host       TEXT,
    suite               TEXT,
    case_id             TEXT,
    status              TEXT,
    outcome             TEXT,
    confidence          TEXT,
    blocked_by          TEXT,
    service             TEXT,
    cve                 TEXT,
    target              TEXT,
    evidence_summary    TEXT,
    input_tokens        INTEGER NOT NULL DEFAULT 0,
    output_tokens       INTEGER NOT NULL DEFAULT 0,
    total_tokens        INTEGER NOT NULL DEFAULT 0,
    estimated_cost_usd  REAL NOT NULL DEFAULT 0.0,
    duration_seconds    REAL NOT NULL DEFAULT 0.0,
    submission_source   TEXT,
    finished_at         TEXT,
    artifact_path       TEXT,
    raw_payload         TEXT
);

CREATE INDEX IF NOT EXISTS idx_runs_dist     ON runs(distributed_job_id);
CREATE INDEX IF NOT EXISTS idx_runs_case     ON runs(case_id);
CREATE INDEX IF NOT EXISTS idx_runs_outcome  ON runs(outcome);
CREATE INDEX IF NOT EXISTS idx_runs_host     ON runs(baseline_host);
CREATE INDEX IF NOT EXISTS idx_runs_finished ON runs(finished_at);
"""


def _utc_now() -> str:
    return datetime.now().isoformat(timespec="seconds")


_INITIALIZED: set[str] = set()


def init_db(path: Path = DEFAULT_DB_PATH) -> Path:
    """Create the SQLite store (and schema) if missing. Idempotent.

    NB: `with sqlite3.connect(...)` only commits/rolls back the transaction —
    it does NOT close the connection. The connection must be closed explicitly
    or it leaks (every leaked connection holds the DB + WAL files open, and
    enough leaks make new connections fail with "unable to open database file").
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()
    _INITIALIZED.add(str(path))
    return path


@contextmanager
def _connect(path: Path = DEFAULT_DB_PATH):
    if str(path) not in _INITIALIZED:
        init_db(path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        yield conn
        conn.commit()
    finally:
        conn.close()


def record_distributed_job(job: Any, *, path: Path = DEFAULT_DB_PATH) -> None:
    """Insert a DistributedJob and its initial host_jobs rows.

    `job` is a `fleet.DistributedJob` instance. We accept Any to avoid an
    import cycle.
    """
    with _connect(path) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO distributed_jobs
            (distributed_job_id, suite, shard_strategy, cases_total, created_at, status, local_dir, repo, agent_command)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                job.distributed_job_id,
                job.suite,
                job.shard_strategy,
                job.cases_total,
                job.created_at,
                "started",
                str(job.local_dir),
                str(job.repo or ""),
                job.agent_command or "",
            ),
        )
        for hj in job.host_jobs:
            conn.execute(
                """
                INSERT OR REPLACE INTO host_jobs
                (distributed_job_id, baseline_host, job_id, session, job_dir, status, shard_size, last_payload, last_seen_at, error)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job.distributed_job_id,
                    hj.baseline_host,
                    hj.job_id,
                    hj.session,
                    hj.job_dir,
                    hj.status,
                    len(hj.cases),
                    json.dumps(hj.last_status_payload, ensure_ascii=False) if hj.last_status_payload else None,
                    datetime.fromtimestamp(hj.last_seen_at).isoformat(timespec="seconds") if hj.last_seen_at else None,
                    hj.error,
                ),
            )


def record_host_status(
    distributed_job_id: str,
    host_jobs: Iterable[Any],
    *,
    path: Path = DEFAULT_DB_PATH,
) -> None:
    """Update the host_jobs table with the latest payload/status from each VM."""
    with _connect(path) as conn:
        for hj in host_jobs:
            conn.execute(
                """
                UPDATE host_jobs
                SET status = ?, last_payload = ?, last_seen_at = ?, error = ?, job_id = ?, session = ?, job_dir = ?
                WHERE distributed_job_id = ? AND baseline_host = ?
                """,
                (
                    hj.status,
                    json.dumps(hj.last_status_payload, ensure_ascii=False) if hj.last_status_payload else None,
                    datetime.fromtimestamp(hj.last_seen_at).isoformat(timespec="seconds") if hj.last_seen_at else _utc_now(),
                    hj.error,
                    hj.job_id,
                    hj.session,
                    hj.job_dir,
                    distributed_job_id,
                    hj.baseline_host,
                ),
            )


def record_runs_from_merge(
    distributed_job_id: str,
    merged_payload: dict[str, Any],
    *,
    path: Path = DEFAULT_DB_PATH,
) -> int:
    """Ingest items from a `distributed_summary.json` payload as `runs` rows."""
    suite = str(merged_payload.get("suite") or "")
    items = merged_payload.get("items") or []
    inserted = 0
    with _connect(path) as conn:
        # Replace status of distributed_job to 'completed'/'partial' based on totals.
        totals = merged_payload.get("totals") or {}
        new_status = "completed" if totals.get("cases_completed", 0) >= totals.get("cases_total", 0) else "partial"
        conn.execute(
            "UPDATE distributed_jobs SET status = ? WHERE distributed_job_id = ?",
            (new_status, distributed_job_id),
        )
        # Wipe previous rows for this distributed_job_id and re-insert (idempotent merges).
        conn.execute("DELETE FROM runs WHERE distributed_job_id = ?", (distributed_job_id,))
        for item in items:
            if not isinstance(item, dict):
                continue
            row = _normalize_run_item(distributed_job_id, suite, item)
            conn.execute(
                """
                INSERT INTO runs
                (distributed_job_id, baseline_host, suite, case_id, status, outcome, confidence, blocked_by,
                 service, cve, target, evidence_summary, input_tokens, output_tokens, total_tokens,
                 estimated_cost_usd, duration_seconds, submission_source, finished_at, artifact_path, raw_payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                row,
            )
            inserted += 1
    return inserted


def _normalize_run_item(distributed_job_id: str, suite: str, item: dict[str, Any]) -> tuple:
    input_tokens = int(item.get("input_tokens") or 0)
    output_tokens = int(item.get("output_tokens") or 0)
    total_tokens = int(item.get("total_tokens") or (input_tokens + output_tokens))
    return (
        distributed_job_id,
        str(item.get("source_host") or item.get("baseline_host") or ""),
        suite,
        str(item.get("case_id") or ""),
        str(item.get("status") or ""),
        str(item.get("outcome") or ""),
        str(item.get("confidence") or ""),
        str(item.get("blocked_by") or ""),
        str(item.get("service") or ""),
        str(item.get("cve") or ""),
        str(item.get("target") or ""),
        str(item.get("evidence_summary") or "")[:2000],
        input_tokens,
        output_tokens,
        total_tokens,
        float(item.get("estimated_cost_usd") or 0.0),
        float(item.get("duration_seconds") or 0.0),
        str(item.get("submission_source") or ""),
        str(item.get("finished_at") or item.get("started_at") or ""),
        str(item.get("run_dir") or item.get("artifact_path") or ""),
        json.dumps(item, ensure_ascii=False, default=str),
    )


def list_distributed_jobs(path: Path = DEFAULT_DB_PATH) -> list[dict[str, Any]]:
    with _connect(path) as conn:
        rows = conn.execute(
            """
            SELECT dj.*, COUNT(r.run_id) AS run_count,
                   SUM(r.estimated_cost_usd) AS total_cost,
                   SUM(r.total_tokens) AS total_tokens,
                   SUM(CASE WHEN r.outcome IN ('confirmed_exploit','probable_vulnerability','blocked_missing_tool','blocked_missing_credentials') THEN 1 ELSE 0 END) AS useful
            FROM distributed_jobs dj
            LEFT JOIN runs r USING (distributed_job_id)
            GROUP BY dj.distributed_job_id
            ORDER BY dj.created_at DESC
            """
        ).fetchall()
        return [dict(r) for r in rows]


def list_runs(
    distributed_job_id: str | None = None,
    outcome: str | None = None,
    case_id: str | None = None,
    limit: int = 500,
    path: Path = DEFAULT_DB_PATH,
) -> list[dict[str, Any]]:
    sql = "SELECT * FROM runs WHERE 1=1"
    args: list[Any] = []
    if distributed_job_id:
        sql += " AND distributed_job_id = ?"
        args.append(distributed_job_id)
    if outcome:
        sql += " AND outcome = ?"
        args.append(outcome)
    if case_id:
        sql += " AND case_id = ?"
        args.append(case_id)
    sql += " ORDER BY finished_at DESC, run_id DESC LIMIT ?"
    args.append(limit)
    with _connect(path) as conn:
        rows = conn.execute(sql, args).fetchall()
        return [dict(r) for r in rows]


def outcome_breakdown(
    distributed_job_id: str | None = None,
    path: Path = DEFAULT_DB_PATH,
) -> list[dict[str, Any]]:
    sql = """
        SELECT outcome, COUNT(*) AS count,
               SUM(estimated_cost_usd) AS cost_usd,
               SUM(total_tokens) AS tokens,
               AVG(duration_seconds) AS avg_duration_seconds
        FROM runs
    """
    args: list[Any] = []
    if distributed_job_id:
        sql += " WHERE distributed_job_id = ?"
        args.append(distributed_job_id)
    sql += " GROUP BY outcome ORDER BY count DESC"
    with _connect(path) as conn:
        rows = conn.execute(sql, args).fetchall()
        return [dict(r) for r in rows]


def case_durations(path: Path = DEFAULT_DB_PATH) -> dict[str, float]:
    """Aggregate per-case median duration for load-aware sharding."""
    with _connect(path) as conn:
        rows = conn.execute(
            """
            SELECT case_id, AVG(duration_seconds) AS avg_dur
            FROM runs
            WHERE duration_seconds > 0
            GROUP BY case_id
            """
        ).fetchall()
        return {r["case_id"]: float(r["avg_dur"]) for r in rows if r["case_id"]}


def run_sql(query: str, params: tuple = (), path: Path = DEFAULT_DB_PATH) -> list[dict[str, Any]]:
    """Run an ad-hoc SELECT and return the rows as dicts."""
    with _connect(path) as conn:
        cur = conn.execute(query, params)
        return [dict(r) for r in cur.fetchall()]


def import_existing_external_runs(
    root: Path,
    distributed_job_id: str = "legacy-import",
    *,
    path: Path = DEFAULT_DB_PATH,
) -> int:
    """Walk an existing `output/external_benchmarks/` tree and import its summaries.

    Useful one-shot migration. Inserts a synthetic distributed_jobs row to host
    them.
    """
    from src.baselines.external_benchmarks import summarize_run_dir  # local import to avoid cycle

    with _connect(path) as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO distributed_jobs
            (distributed_job_id, suite, shard_strategy, cases_total, created_at, status, local_dir, repo, agent_command)
            VALUES (?, '', 'imported', 0, ?, 'imported', ?, '', '')
            """,
            (distributed_job_id, _utc_now(), str(root)),
        )

    inserted = 0
    run_dirs = sorted(p.parent for p in root.rglob("result.json"))
    for run_dir in run_dirs:
        summary = summarize_run_dir(run_dir)
        if not summary:
            continue
        item = dict(summary)
        item.setdefault("source_host", "")
        item.setdefault("artifact_path", str(run_dir))
        with _connect(path) as conn:
            conn.execute(
                """
                INSERT INTO runs
                (distributed_job_id, baseline_host, suite, case_id, status, outcome, confidence, blocked_by,
                 service, cve, target, evidence_summary, input_tokens, output_tokens, total_tokens,
                 estimated_cost_usd, duration_seconds, submission_source, finished_at, artifact_path, raw_payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                _normalize_run_item(distributed_job_id, str(summary.get("suite") or ""), item),
            )
        inserted += 1
    return inserted
