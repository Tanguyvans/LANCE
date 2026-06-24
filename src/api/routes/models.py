"""Models API — returns the list of available models grouped by provider.

Supports two providers:
- `openrouter` — pay-per-token, 19 curated models, prices fetched live from OpenRouter
- `minimax` — MiniMax Coding Plan (subscription), calls api.minimax.io/v1 directly
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from src.agent.pricing import _load_pricing

router = APIRouter()


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


class ModelPatch(BaseModel):
    provider: str | None = None
    label: str | None = None
    recommended: bool | None = None
    enabled: bool | None = None
    input_per_mtok: float | None = None
    output_per_mtok: float | None = None
    base_url: str | None = None
    subscription: bool | None = None


# Curated list of models to show in the dashboard.
# Schema: (slug, label, recommended, provider)
#   - slug       : model ID passed to the LLM provider
#   - label      : display name in the dropdown
#   - recommended: if True, auto-selected by default
#   - provider   : "openrouter" (pay-per-token) or "minimax" (subscription plan)
CURATED_MODELS: list[tuple[str, str, bool, str]] = [
    # OpenRouter (pay-per-token)
    ("deepseek/deepseek-chat-v3-0324",      "deepseek-v3",                True,  "openrouter"),
    ("deepseek/deepseek-v3.2",              "deepseek-v3.2",              False, "openrouter"),
    ("deepseek/deepseek-v3.2-exp",          "deepseek-v3.2-exp",          False, "openrouter"),
    ("anthropic/claude-sonnet-4",           "claude-sonnet-4",            False, "openrouter"),
    ("anthropic/claude-sonnet-4.5",         "claude-sonnet-4.5",          False, "openrouter"),
    ("openai/gpt-4o",                       "gpt-4o",                     False, "openrouter"),
    ("google/gemini-2.0-flash-001",         "gemini-2.0-flash",           False, "openrouter"),
    ("google/gemini-2.5-flash",             "gemini-2.5-flash",           False, "openrouter"),
    ("google/gemini-2.5-pro-preview",       "gemini-2.5-pro",             False, "openrouter"),
    ("meta-llama/llama-3.3-70b-instruct",   "llama-3.3-70b",              False, "openrouter"),
    ("qwen/qwen-plus",                      "qwen-plus",                  False, "openrouter"),
    ("qwen/qwen-max",                       "qwen-max",                   False, "openrouter"),
    ("qwen/qwen3-max",                      "qwen3-max",                  False, "openrouter"),
    ("qwen/qwen3.5-plus-02-15",             "qwen3.5-plus",               False, "openrouter"),
    ("qwen/qwen3.6-plus",                   "qwen3.6-plus",               False, "openrouter"),
    ("qwen/qwen3-coder",                    "qwen3-coder",                False, "openrouter"),
    ("minimax/minimax-m2",                  "minimax-m2",                 False, "openrouter"),
    ("minimax/minimax-m2.5",                "minimax-m2.5",               False, "openrouter"),
    ("minimax/minimax-m2.7",                "minimax-m2.7",               False, "openrouter"),
    # MiniMax Coding Plan (subscription, $10/mo Starter — 1500 req/5h on MiniMax-M2.7)
    ("MiniMax-M2.7",                        "minimax-m2.7 (plan)",        False, "minimax"),
    ("MiniMax-M2.5",                        "minimax-m2.5 (plan)",        False, "minimax"),
    ("MiniMax-M2",                          "minimax-m2 (plan)",          False, "minimax"),
]


def _entry(slug, label, recommended, provider, subscription, pricing,
           db_in=None, db_out=None):
    """Build one response entry, enriched with live OpenRouter pricing.

    Live $/M pricing wins; falls back to the price stored in the DB (if any).
    Subscription models have no per-token price and are always 'available'.
    """
    if subscription:
        return {
            "id": slug,
            "label": label + (" (recommandé)" if recommended else ""),
            "recommended": recommended,
            "available": True,
            "provider": provider,
            "subscription": True,
            "input_per_mtok": None,
            "output_per_mtok": None,
        }
    price = pricing.get(slug)
    in_price = round(price["input"], 4) if price else (round(db_in, 4) if db_in is not None else None)
    out_price = round(price["output"], 4) if price else (round(db_out, 4) if db_out is not None else None)
    return {
        "id": slug,
        "label": label + (" (recommandé)" if recommended else ""),
        "recommended": recommended,
        "available": (price is not None) or (in_price is not None),
        "provider": provider,
        "subscription": False,
        "input_per_mtok": in_price,
        "output_per_mtok": out_price,
    }


@router.get("")
def list_models() -> dict:
    """Return the list of models with per-provider metadata.

    Source of truth is the SQLite ``models`` table when populated (seed via
    ``python3 -m src.db.seed``); otherwise it falls back to the hardcoded
    ``CURATED_MODELS`` list. OpenRouter models are enriched with live $/M
    pricing (24h cache); MiniMax Plan / local models are marked accordingly.
    """
    pricing = _load_pricing()

    # Preferred path: read curated models from the DB so they can be edited
    # without touching the code. Any failure falls back to the hardcoded list.
    try:
        from src.db.database import list_models as db_list_models
        rows = db_list_models(enabled_only=True)
    except Exception:
        rows = []

    if rows:
        models = [
            _entry(
                r["slug"], r["label"] or r["slug"], bool(r["recommended"]),
                r["provider"] or "openrouter",
                bool(r["subscription"]) or (r["provider"] == "minimax"),
                pricing, r["input_per_mtok"], r["output_per_mtok"],
            )
            for r in rows
        ]
        return {"models": models}

    models = [
        _entry(slug, label, recommended, provider, provider == "minimax", pricing)
        for slug, label, recommended, provider in CURATED_MODELS
    ]
    return {"models": models}


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


@router.post("")
def create_model(body: ModelCreate) -> dict:
    """Create (or upsert) a model. The provider must already exist."""
    db = _require_db()
    if db.get_provider(body.provider) is None:
        raise HTTPException(status_code=400, detail=f"Provider inconnu : {body.provider}")
    db.upsert_model(
        slug=body.slug, label=body.label, provider=body.provider,
        recommended=body.recommended, enabled=body.enabled,
        input_per_mtok=body.input_per_mtok, output_per_mtok=body.output_per_mtok,
        base_url=body.base_url, subscription=body.subscription,
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
    db.upsert_model(
        slug=slug, label=merged.get("label"), provider=merged.get("provider"),
        recommended=bool(merged.get("recommended")), enabled=bool(merged.get("enabled")),
        input_per_mtok=merged.get("input_per_mtok"), output_per_mtok=merged.get("output_per_mtok"),
        base_url=merged.get("base_url"), subscription=bool(merged.get("subscription")),
    )
    return _model_out(db.get_model(slug))


@router.delete("/{slug:path}")
def remove_model(slug: str) -> dict:
    """Delete a model from the registry."""
    db = _require_db()
    if not db.delete_model(slug):
        raise HTTPException(status_code=404, detail=f"Modèle introuvable : {slug}")
    return {"ok": True}
