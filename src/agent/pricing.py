"""Dynamic model pricing from OpenRouter API.

Fetches the full model catalog from https://openrouter.ai/api/v1/models once per day
and caches it locally. Falls back to hardcoded pricing in cost_tracker.py if the API
is unavailable.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path

log = logging.getLogger(__name__)

OPENROUTER_MODELS_URL = "https://openrouter.ai/api/v1/models"
CACHE_PATH = Path(__file__).parent.parent.parent / "data" / "openrouter_models_cache.json"
CACHE_TTL_SECONDS = 24 * 3600  # 24 hours

_memory_cache: dict[str, dict[str, float]] | None = None


def _fetch_openrouter_pricing() -> dict[str, dict[str, float]]:
    """Fetch the full model catalog from OpenRouter and convert to our pricing format.

    OpenRouter returns pricing per token as strings (e.g. "0.000003" = $3/M tokens).
    We convert to $/M tokens for consistency with the hardcoded PRICING dict.
    """
    import requests

    try:
        resp = requests.get(OPENROUTER_MODELS_URL, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        log.warning("Failed to fetch OpenRouter models: %s", e)
        return {}

    pricing: dict[str, dict[str, float]] = {}
    for model in data.get("data", []):
        model_id = model.get("id", "")
        if not model_id:
            continue
        p = model.get("pricing", {}) or {}
        try:
            prompt_price = float(p.get("prompt", "0") or "0")
            completion_price = float(p.get("completion", "0") or "0")
        except (TypeError, ValueError):
            continue
        # Convert per-token price to per-million-token price
        pricing[model_id] = {
            "input": prompt_price * 1_000_000,
            "output": completion_price * 1_000_000,
        }
    return pricing


def _load_cache() -> dict[str, dict[str, float]] | None:
    """Load the cached pricing if it exists and is fresh."""
    if not CACHE_PATH.exists():
        return None
    try:
        mtime = CACHE_PATH.stat().st_mtime
        if time.time() - mtime > CACHE_TTL_SECONDS:
            log.debug("OpenRouter pricing cache is stale")
            return None
        content = CACHE_PATH.read_text(encoding="utf-8")
        data = json.loads(content)
        return data.get("pricing", {})
    except Exception as e:
        log.warning("Failed to read pricing cache: %s", e)
        return None


def _save_cache(pricing: dict[str, dict[str, float]]) -> None:
    """Persist the pricing to the cache file."""
    try:
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        CACHE_PATH.write_text(
            json.dumps({"fetched_at": time.time(), "pricing": pricing}, indent=2),
            encoding="utf-8",
        )
    except Exception as e:
        log.warning("Failed to write pricing cache: %s", e)


def _load_pricing() -> dict[str, dict[str, float]]:
    """Get the full pricing catalog, using cache or fetching from API."""
    global _memory_cache
    if _memory_cache is not None:
        return _memory_cache

    # Try disk cache first
    cached = _load_cache()
    if cached:
        _memory_cache = cached
        return cached

    # Fetch from API
    log.info("Fetching OpenRouter model pricing...")
    fresh = _fetch_openrouter_pricing()
    if fresh:
        _save_cache(fresh)
        _memory_cache = fresh
        return fresh

    # API failed, return empty (caller will fall back to hardcoded)
    _memory_cache = {}
    return {}


def get_dynamic_pricing(model: str) -> dict[str, float] | None:
    """Return {"input": float, "output": float} in $/M tokens for the given model.

    Returns None if the model is not in the OpenRouter catalog (caller should fall back
    to hardcoded pricing).
    """
    if not model:
        return None
    pricing = _load_pricing()
    # Try exact match first
    if model in pricing:
        return pricing[model]
    # Try lowercase match
    lower = model.lower()
    for k, v in pricing.items():
        if k.lower() == lower:
            return v
    return None


def refresh_pricing() -> bool:
    """Force a refresh of the pricing cache. Returns True on success."""
    global _memory_cache
    _memory_cache = None
    if CACHE_PATH.exists():
        CACHE_PATH.unlink()
    fresh = _fetch_openrouter_pricing()
    if fresh:
        _save_cache(fresh)
        _memory_cache = fresh
        return True
    return False
