"""Models API — user-managed registry models for the dashboard selector."""
from __future__ import annotations

import logging
import os
from typing import Literal

from fastapi import APIRouter, HTTPException

from pydantic import BaseModel, Field

router = APIRouter()
log = logging.getLogger(__name__)


def _require_db():
    """Ensure the SQLite DB is reachable; raise 503 otherwise.

    Editing models requires the DB (the hardcoded list is read-only). Returns
    the database module so callers can use its helpers.
    """
    try:
        from src.db import database as db
        db.init_db()
        return db
    except Exception as exc:  # noqa: BLE001 — surface any DB init failure as 503
        raise HTTPException(status_code=503, detail=f"Base de données indisponible : {exc}")


def _model_out(row: dict) -> dict:
    """Normalise a raw model row (int flags → bool) for JSON responses."""
    from src.agent.execution_profiles import resolve_execution_profile_for_model

    resolution = resolve_execution_profile_for_model(
        "auto", row.get("slug"), model_metadata=row
    )
    return {
        "slug": row["slug"],
        "label": row.get("label"),
        "provider": row.get("provider"),
        "recommended": bool(row.get("recommended")),
        "enabled": bool(row.get("enabled")),
        "input_per_mtok": row.get("input_per_mtok"),
        "output_per_mtok": row.get("output_per_mtok"),
        "base_url": row.get("base_url"),
        "subscription": bool(row.get("subscription")),
        "parameter_count_b": row.get("parameter_count_b"),
        "active_parameter_count_b": row.get("active_parameter_count_b"),
        "profile_policy": row.get("profile_policy") or "auto",
        "effective_profile": resolution.profile.name,
        "profile_resolution_basis": resolution.resolution_basis,
        "profile_threshold_b": resolution.threshold_b,
    }


# api_key is intentionally absent — keys live in .env, only api_key_env is stored.
class ModelCreate(BaseModel):
    slug: str
    provider: str
    label: str | None = None
    recommended: bool = False
    enabled: bool = True
    input_per_mtok: float | None = None
    output_per_mtok: float | None = None
    base_url: str | None = None
    subscription: bool = False
    parameter_count_b: float | None = Field(default=None, gt=0)
    active_parameter_count_b: float | None = Field(default=None, gt=0)
    profile_policy: Literal["auto", "compact", "full"] = "auto"


class ModelPatch(BaseModel):
    provider: str | None = None
    label: str | None = None
    recommended: bool | None = None
    enabled: bool | None = None
    input_per_mtok: float | None = None
    output_per_mtok: float | None = None
    base_url: str | None = None
    subscription: bool | None = None
    parameter_count_b: float | None = Field(default=None, gt=0)
    active_parameter_count_b: float | None = Field(default=None, gt=0)
    profile_policy: Literal["auto", "compact", "full"] | None = None


# Minimal offline fallback when the registry is empty or unavailable.
# Schema: (slug, label, recommended, provider)
#   - slug       : model ID passed to the LLM provider
#   - label      : display name in the dropdown
#   - recommended: if True, auto-selected by default
#   - provider   : registry provider name
CURATED_MODELS: list[tuple[str, str, bool, str]] = [
    # MiniMax Coding Plan (subscription, $10/mo Starter — 1500 req/5h on MiniMax-M2.7)
    ("MiniMax-M2.7",                        "minimax-m2.7 (plan)",        False, "minimax"),
    ("MiniMax-M2.5",                        "minimax-m2.5 (plan)",        False, "minimax"),
    ("MiniMax-M2",                          "minimax-m2 (plan)",          False, "minimax"),
]


# provider name -> env var holding its API key (fallback when the DB is absent)
_STATIC_KEY_ENV = {
    "minimax": "MINIMAX_API_KEY",
    "glm": "GLM_API_KEY",
    "qwen": "DASHSCOPE_API_KEY",
    "local": "LOCAL_API_KEY",
}


def _key_present(provider, key_env_map):
    """True if the provider's API key env var is set — the real availability test.

    A local (Ollama/vLLM) model has no per-token price, so it must NOT be gated
    on pricing; it's available as soon as its key env (any non-empty value) is set.
    """
    env = key_env_map.get(provider) or _STATIC_KEY_ENV.get(provider)
    if not env or provider.startswith("local"):
        return True
    return bool(os.environ.get(env))


def _entry(slug, label, recommended, provider, subscription,
           db_in=None, db_out=None, key_present=True, **metadata):
    """Build one response entry using prices configured in the registry.

    Subscription models have no per-token price.
    A model is available when its provider key is configured (``key_present``),
    independently of whether pricing is known (local models have no price).
    """
    if subscription:
        return {
            "id": slug,
            "label": label + (" (recommandé)" if recommended else ""),
            "recommended": recommended,
            "available": key_present,
            "provider": provider,
            "subscription": True,
            "input_per_mtok": None,
            "output_per_mtok": None,
            **metadata,
        }
    in_price = round(db_in, 4) if db_in is not None else None
    out_price = round(db_out, 4) if db_out is not None else None
    return {
        "id": slug,
        "label": label + (" (recommandé)" if recommended else ""),
        "recommended": recommended,
        "available": key_present,
        "provider": provider,
        "subscription": False,
        "input_per_mtok": in_price,
        "output_per_mtok": out_price,
        **metadata,
    }


@router.get("")
def list_models(refresh: bool = False) -> dict:
    """Read the selector's registry on every request, including refresh.

    OpenRouter, Codex and the removed Anthropic adapter are excluded from launch
    choices. Their historical registry entries remain available through the
    administration endpoint.
    """

    # Preferred path: read curated models from the DB so they can be edited
    # without touching the code. Any failure falls back to the hardcoded list.
    try:
        from src.db import database as db

        # The public selector is often the first DB-backed endpoint hit after a
        # deployment. Ensure legacy databases are migrated before querying the
        # profile metadata columns added to the models table.
        db.init_db()
        rows = db.list_models_admin()
    except Exception as exc:
        log.warning("Model registry unavailable; using static fallback: %s", exc)
        rows = []

    # provider -> api_key_env, so a model is "available" when its key is set
    try:
        from src.db.database import list_providers
        key_env = {p["name"]: p.get("api_key_env") for p in list_providers()}
    except Exception:
        key_env = {}

    models: list[dict] = []

    # Registry providers such as MiniMax and local inference remain editable.
    for row in rows:
        provider = row.get("provider")
        if not provider or provider in {"openrouter", "codex", "anthropic"} or not bool(row.get("enabled")):
            continue
        models.append(_entry(
            row["slug"], row.get("label") or row["slug"],
            bool(row.get("recommended")), provider,
            bool(row.get("subscription")) or provider == "minimax",
            row.get("input_per_mtok"), row.get("output_per_mtok"),
            key_present=_key_present(provider, key_env),
            description="",
            tool_capable=True,
        ))

    # Preserve the subscription fallback for an empty/unavailable registry.
    if not rows:
        for slug, label, recommended, provider in CURATED_MODELS:
            models.append(_entry(
                slug, label, recommended, provider, provider == "minimax",
                key_present=_key_present(provider, key_env), tool_capable=True,
            ))

    providers = {}
    for model in models:
        status = providers.setdefault(model["provider"], {
            "available": model["available"], "model_count": 0,
        })
        status["model_count"] += 1
    return {
        "models": models,
        "providers": providers,
    }


@router.get("/registry")
def model_registry() -> dict:
    """Admin view: ALL models (incl. disabled, raw fields) + providers.

    Used by the dashboard's management panel. Requires the DB.
    """
    db = _require_db()
    return {
        "models": [_model_out(m) for m in db.list_models_admin()],
        "providers": db.list_providers(),
    }


def _validate_parameter_counts(total: float | None, active: float | None) -> None:
    if total is not None and active is not None and active > total:
        raise HTTPException(
            status_code=422,
            detail="Les paramètres actifs ne peuvent pas dépasser les paramètres totaux",
        )


@router.post("")
def create_model(body: ModelCreate) -> dict:
    """Create (or upsert) a model. The provider must already exist."""
    db = _require_db()
    if db.get_provider(body.provider) is None:
        raise HTTPException(status_code=400, detail=f"Provider inconnu : {body.provider}")
    _validate_parameter_counts(body.parameter_count_b, body.active_parameter_count_b)
    db.upsert_model(
        slug=body.slug, label=body.label, provider=body.provider,
        recommended=body.recommended, enabled=body.enabled,
        input_per_mtok=body.input_per_mtok, output_per_mtok=body.output_per_mtok,
        base_url=body.base_url, subscription=body.subscription,
        parameter_count_b=body.parameter_count_b,
        active_parameter_count_b=body.active_parameter_count_b,
        profile_policy=body.profile_policy,
    )
    return _model_out(db.get_model(body.slug))


@router.patch("/{slug:path}")
def update_model(slug: str, body: ModelPatch) -> dict:
    """Partially update an existing model (any field except the slug)."""
    db = _require_db()
    existing = db.get_model(slug)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"Modèle introuvable : {slug}")
    patch = body.model_dump(exclude_unset=True)
    merged = {**existing, **patch}
    if patch.get("provider") and db.get_provider(merged["provider"]) is None:
        raise HTTPException(status_code=400, detail=f"Provider inconnu : {merged['provider']}")
    _validate_parameter_counts(
        merged.get("parameter_count_b"), merged.get("active_parameter_count_b")
    )
    db.upsert_model(
        slug=slug, label=merged.get("label"), provider=merged.get("provider"),
        recommended=bool(merged.get("recommended")), enabled=bool(merged.get("enabled")),
        input_per_mtok=merged.get("input_per_mtok"), output_per_mtok=merged.get("output_per_mtok"),
        base_url=merged.get("base_url"), subscription=bool(merged.get("subscription")),
        parameter_count_b=merged.get("parameter_count_b"),
        active_parameter_count_b=merged.get("active_parameter_count_b"),
        profile_policy=merged.get("profile_policy") or "auto",
    )
    return _model_out(db.get_model(slug))


@router.delete("/{slug:path}")
def remove_model(slug: str) -> dict:
    """Delete a model from the registry."""
    db = _require_db()
    if not db.delete_model(slug):
        raise HTTPException(status_code=404, detail=f"Modèle introuvable : {slug}")
    return {"ok": True}
