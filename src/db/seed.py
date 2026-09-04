"""Seed and backfill the LANCE SQLite database.

Usage::

    python3 -m src.db.seed

Idempotent: creates the schema, upserts providers and offline fallback models,
then backfills runs already on disk. OpenRouter and Codex catalogs are dynamic
and are therefore not duplicated in SQLite.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from src.db.database import (
    get_conn,
    get_model,
    init_db,
    record_phase_usage,
    record_run,
    record_scores,
    upsert_model,
    upsert_provider,
)

log = logging.getLogger(__name__)

_ROOT = Path(__file__).resolve().parents[2]
_OUTPUT_DIR = _ROOT / "output" / "agent"

# Local Ollama model tags (provider=local), num_ctx-tuned, created on the Ollama
# server. The local provider's base_url comes from the OLLAMA_BASE_URL env var.
# recommended = best quality/speed fit that stays fully on a 16GB GPU.
_LOCAL_MODELS: list[tuple[str, str, bool]] = [
    ("qwen3-14b-32k:latest",   "Qwen3 14B local (32k)",            True),
    ("gemma4-12b-32k:latest",  "Gemma4 12B local (32k)",           False),
    ("qwen3.5-9b-32k:latest",  "Qwen3.5 9B local (32k)",           False),
    ("qwen3.5-27b-32k:latest", "Qwen3.5 27B local (32k, offload)", False),
]

_MODEL_PARAMETERS: dict[str, tuple[float, float | None]] = {
    "meta-llama/llama-3.3-70b-instruct": (70.0, None),
    "google/gemma-4-31b-it": (31.0, None),
    "google/gemma-4-26b-a4b-it": (26.0, 4.0),
    "qwen/qwen3-30b-a3b": (30.0, 3.0),
    "qwen3-14b-32k:latest": (14.0, None),
    "gemma4-12b-32k:latest": (12.0, None),
    "qwen3.5-9b-32k:latest": (9.0, None),
    "qwen3.5-27b-32k:latest": (27.0, None),
}


def _parameter_metadata(slug: str) -> dict:
    existing = get_model(slug) or {}
    known_total, known_active = _MODEL_PARAMETERS.get(slug, (None, None))
    return {
        "parameter_count_b": known_total or existing.get("parameter_count_b"),
        "active_parameter_count_b": (
            known_active or existing.get("active_parameter_count_b")
        ),
        "profile_policy": existing.get("profile_policy") or "auto",
    }


# Local OpenAI-compatible inference endpoint (ollama / vLLM). Override per host.
_OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1")


def seed_providers() -> int:
    """Seed cloud providers from the agent registry + anthropic + a local one."""
    from src.agent.provider import OPENAI_PROVIDERS

    count = 0
    for name, cfg in OPENAI_PROVIDERS.items():
        upsert_provider(
            name=name,
            base_url=cfg.get("base_url"),
            api_key_env=cfg.get("api_key_env"),
            default_model=cfg.get("default_model"),
            kind="cloud",
        )
        count += 1

    # Anthropic uses the native SDK (no base_url in OPENAI_PROVIDERS).
    upsert_provider(
        name="anthropic",
        base_url=None,
        api_key_env="ANTHROPIC_API_KEY",
        default_model="claude-sonnet-4-20250514",
        kind="cloud",
    )
    count += 1

    # Authentication and models are resolved from the local Codex session at
    # runtime; no OAuth token or account identity is stored in SQLite.
    upsert_provider(
        name="codex",
        base_url=None,
        api_key_env=None,
        default_model=None,
        kind="subscription",
    )
    count += 1

    # Local OpenAI-compatible endpoint (ollama / vLLM). base_url from OLLAMA_BASE_URL
    # so each host points at its own/the shared Ollama; editable later via the UI.
    upsert_provider(
        name="local",
        base_url=_OLLAMA_BASE_URL,
        api_key_env="LOCAL_API_KEY",
        default_model="qwen3-14b-32k:latest",
        kind="local",
    )
    count += 1
    return count


def seed_models() -> int:
    """Seed only offline fallbacks and user-managed local models."""
    from src.api.routes.models import CURATED_MODELS

    seen: set[str] = set()
    for slug, label, recommended, provider in CURATED_MODELS:
        upsert_model(
            slug=slug,
            label=label,
            provider=provider,
            recommended=recommended,
            subscription=(provider == "minimax"),
            **_parameter_metadata(slug),
        )
        seen.add(slug)

    for slug, label, recommended in _LOCAL_MODELS:
        upsert_model(
            slug=slug, label=label, provider="local",
            recommended=recommended, **_parameter_metadata(slug),
        )
        seen.add(slug)

    return len(seen)


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def backfill_runs() -> int:
    """Insert runs already present on disk. Idempotent (upsert on run_dir)."""
    if not _OUTPUT_DIR.exists():
        return 0

    n = 0
    for d in sorted(_OUTPUT_DIR.iterdir()):
        if not d.is_dir():
            continue
        run_meta = _load_json(d / "run_meta.json")
        scen_meta = _load_json(d / "scenario_meta.json")
        cost = _load_json(d / "cost_summary.json")
        if not (run_meta or scen_meta or cost):
            continue

        scenario_id = scen_meta.get("scenario_id")
        model = scen_meta.get("model") or run_meta.get("model") or cost.get("model")
        from src.agent.codex_app_server import is_codex_model
        provider = (
            "codex" if model and is_codex_model(str(model))
            else "minimax" if model and "/" not in str(model)
            else "openrouter"
        )
        status = "completed" if (d / "06_report.md").exists() else "partial"

        run_id = record_run({
            "run_dir": str(d),
            "ts": d.name,
            "scenario_id": scenario_id,
            "model": model,
            "provider": provider,
            "status": status,
            "cost_usd": cost.get("total_cost_usd"),
            "tokens_in": cost.get("total_input_tokens"),
            "tokens_out": cost.get("total_output_tokens"),
            "git_commit": scen_meta.get("git_commit") or run_meta.get("git_commit"),
        })
        if run_id is None:
            continue
        n += 1

        if cost.get("phases"):
            record_phase_usage(run_id, cost["phases"])

        _backfill_scores(run_id, d, scenario_id)

    return n


def _backfill_scores(run_id: int, run_dir: Path, scenario_id) -> None:
    """Compute and store benchmark scores for a run (best effort)."""
    if scenario_id is None or not (run_dir / "03_vuln_analysis.json").exists():
        return
    from src.benchmark.scenario_exports import resolve_ground_truth_path
    gt_path = resolve_ground_truth_path(scenario_id)
    if not gt_path.exists():
        return
    try:
        from src.benchmark.evaluator import evaluate

        r = evaluate(run_dir, gt_path)
        record_scores(
            run_id,
            scenario_id=scenario_id,
            precision=r.precision,
            recall=r.recall,
            f1=r.f1_score,
            weighted=r.weighted_score,
            exploitation_coverage=r.exploitation_coverage,
            mhr_1=r.mhr_1,
            mhr_2=r.mhr_2,
            mhr_3=r.mhr_3,
            tp=r.true_positives,
            fp=r.false_positives,
            fn=r.false_negatives,
        )
    except Exception as exc:  # noqa: BLE001 — backfill is best effort
        log.warning("score backfill failed for %s: %s", run_dir.name, exc)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    init_db()
    n_prov = seed_providers()
    n_models = seed_models()
    n_runs = backfill_runs()

    with get_conn() as conn:
        tot_prov = conn.execute("SELECT COUNT(*) FROM providers").fetchone()[0]
        tot_models = conn.execute("SELECT COUNT(*) FROM models").fetchone()[0]
        tot_runs = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]

    print("LANCE DB seeded:")
    print(f"  providers : {n_prov} upserted ({tot_prov} total)")
    print(f"  models    : {n_models} upserted ({tot_models} total)")
    print(f"  runs      : {n_runs} backfilled ({tot_runs} total)")


if __name__ == "__main__":
    main()
