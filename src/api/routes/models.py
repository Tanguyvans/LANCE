"""Models API — returns the list of available models grouped by provider.

Supports two providers:
- `openrouter` — pay-per-token, 19 curated models, prices fetched live from OpenRouter
- `minimax` — MiniMax Coding Plan (subscription), calls api.minimax.io/v1 directly
"""
from __future__ import annotations

from fastapi import APIRouter

from src.agent.pricing import _load_pricing

router = APIRouter()


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
