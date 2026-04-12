"""Models API — returns the list of available OpenRouter models with pricing."""
from __future__ import annotations

from fastapi import APIRouter

from src.agent.pricing import _load_pricing

router = APIRouter()


# Curated list of models to show in the dashboard (slug → display name)
# Keeps the dropdown focused on tool-calling capable models.
CURATED_MODELS: list[tuple[str, str, bool]] = [
    # (slug, label, recommended)
    ("deepseek/deepseek-chat-v3-0324",      "deepseek-v3",                True),
    ("deepseek/deepseek-v3.2",              "deepseek-v3.2",              False),
    ("deepseek/deepseek-v3.2-exp",          "deepseek-v3.2-exp",          False),
    ("anthropic/claude-sonnet-4",           "claude-sonnet-4",            False),
    ("anthropic/claude-sonnet-4.5",         "claude-sonnet-4.5",          False),
    ("openai/gpt-4o",                       "gpt-4o",                     False),
    ("google/gemini-2.0-flash-001",         "gemini-2.0-flash",           False),
    ("google/gemini-2.5-flash",             "gemini-2.5-flash",           False),
    ("google/gemini-2.5-pro-preview",       "gemini-2.5-pro",             False),
    ("meta-llama/llama-3.3-70b-instruct",   "llama-3.3-70b",              False),
    ("qwen/qwen-plus",                      "qwen-plus",                  False),
    ("qwen/qwen-max",                       "qwen-max",                   False),
    ("qwen/qwen3-max",                      "qwen3-max",                  False),
    ("qwen/qwen3.5-plus-02-15",             "qwen3.5-plus",               False),
    ("qwen/qwen3.6-plus",                   "qwen3.6-plus",               False),
    ("qwen/qwen3-coder",                    "qwen3-coder",                False),
    ("minimax/minimax-m2",                  "minimax-m2",                 False),
    ("minimax/minimax-m2.5",                "minimax-m2.5",               False),
    ("minimax/minimax-m2.7",                "minimax-m2.7",               False),
]


@router.get("")
def list_models() -> dict:
    """Return the curated list of models with their current pricing from OpenRouter.

    Dynamically enriches each curated entry with the latest input/output $/M prices
    fetched from OpenRouter (24h cache). Entries not found in the API are marked
    as unavailable but kept in the list.
    """
    pricing = _load_pricing()
    models = []
    for slug, label, recommended in CURATED_MODELS:
        price = pricing.get(slug)
        models.append({
            "id": slug,
            "label": label + (" (recommandé)" if recommended else ""),
            "recommended": recommended,
            "available": price is not None,
            "input_per_mtok": round(price["input"], 4) if price else None,
            "output_per_mtok": round(price["output"], 4) if price else None,
        })
    return {"models": models}
