"""Dynamic OpenRouter catalog and pricing.

Only text-output models that advertise tool calling are loaded because every
LANCE phase depends on function tools.  The response is cached locally so the
dashboard remains usable during a temporary OpenRouter outage.
"""
from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

OPENROUTER_MODELS_URL = "https://openrouter.ai/api/v1/models"
CACHE_PATH = Path(__file__).parent.parent.parent / "data" / "openrouter_models_cache.json"
CACHE_TTL_SECONDS = 3600

_memory_cache: dict[str, dict[str, float]] | None = None
_memory_catalog: list[dict[str, Any]] | None = None


def _fetch_openrouter_catalog() -> list[dict[str, Any]]:
    """Fetch current tool-capable text models from OpenRouter."""
    import requests

    try:
        headers = {}
        if os.environ.get("OPENROUTER_API_KEY"):
            headers["Authorization"] = f"Bearer {os.environ['OPENROUTER_API_KEY']}"
        resp = requests.get(
            OPENROUTER_MODELS_URL,
            params={
                "supported_parameters": "tools",
                "output_modalities": "text",
                "sort": "most-popular",
            },
            headers=headers,
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        log.warning("Failed to fetch OpenRouter models: %s", e)
        return []

    catalog: list[dict[str, Any]] = []
    for model in data.get("data", []):
        model_id = model.get("id", "")
        if not model_id:
            continue
        supported = model.get("supported_parameters") or []
        output_modalities = (model.get("architecture") or {}).get("output_modalities") or []
        if "tools" not in supported or (output_modalities and "text" not in output_modalities):
            continue
        catalog.append({
            "id": model_id,
            "name": model.get("name") or model_id,
            "description": model.get("description") or "",
            "context_length": model.get("context_length"),
            "created": model.get("created"),
            "pricing": model.get("pricing") or {},
            "supported_parameters": supported,
            "architecture": model.get("architecture") or {},
        })
    return catalog


def _catalog_pricing(catalog: list[dict[str, Any]]) -> dict[str, dict[str, float]]:
    """Convert OpenRouter's per-token strings to USD per million tokens."""
    pricing: dict[str, dict[str, float]] = {}
    for model in catalog:
        raw = model.get("pricing") or {}
        try:
            prompt_price = float(raw.get("prompt", "0") or "0")
            completion_price = float(raw.get("completion", "0") or "0")
        except (TypeError, ValueError):
            continue
        pricing[model["id"]] = {
            "input": prompt_price * 1_000_000,
            "output": completion_price * 1_000_000,
        }
    return pricing


def _fetch_openrouter_pricing() -> dict[str, dict[str, float]]:
    """Compatibility helper retained for callers and tests."""
    return _catalog_pricing(_fetch_openrouter_catalog())


def _load_cache() -> dict[str, Any] | None:
    """Load the cached catalog if it exists and is fresh."""
    if not CACHE_PATH.exists():
        return None
    try:
        mtime = CACHE_PATH.stat().st_mtime
        if time.time() - mtime > CACHE_TTL_SECONDS:
            log.debug("OpenRouter pricing cache is stale")
            return None
        content = CACHE_PATH.read_text(encoding="utf-8")
        data = json.loads(content)
        return data
    except Exception as e:
        log.warning("Failed to read pricing cache: %s", e)
        return None


def _save_cache(catalog: list[dict[str, Any]]) -> None:
    """Persist catalog and derived pricing for backward compatibility."""
    try:
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        CACHE_PATH.write_text(
            json.dumps(
                {
                    "fetched_at": time.time(),
                    "catalog": catalog,
                    "pricing": _catalog_pricing(catalog),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    except Exception as e:
        log.warning("Failed to write pricing cache: %s", e)


def _load_openrouter_catalog(*, force_refresh: bool = False) -> list[dict[str, Any]]:
    """Get the current OpenRouter model catalog, using the one-hour cache."""
    global _memory_cache, _memory_catalog
    previous_catalog = _memory_catalog
    previous_pricing = _memory_cache
    if force_refresh:
        _memory_cache = None
        _memory_catalog = None
    if _memory_catalog is not None:
        return _memory_catalog

    cached = None if force_refresh else _load_cache()
    if cached and isinstance(cached.get("catalog"), list):
        _memory_catalog = cached["catalog"]
        _memory_cache = cached.get("pricing") or _catalog_pricing(_memory_catalog)
        return _memory_catalog

    log.info("Fetching OpenRouter tool-capable model catalog...")
    fresh = _fetch_openrouter_catalog()
    if fresh:
        _save_cache(fresh)
        _memory_catalog = fresh
        _memory_cache = _catalog_pricing(fresh)
        return fresh

    if previous_catalog:
        _memory_catalog = previous_catalog
        _memory_cache = previous_pricing or _catalog_pricing(previous_catalog)
        return previous_catalog

    # A legacy cache has pricing only. Keep it useful for cost estimation even
    # though it cannot populate the richer model selector.
    if cached and isinstance(cached.get("pricing"), dict):
        _memory_cache = cached["pricing"]
    _memory_catalog = []
    return []


def _load_pricing() -> dict[str, dict[str, float]]:
    """Get pricing derived from the same catalog shown by the dashboard."""
    global _memory_cache
    if _memory_cache is not None:
        return _memory_cache
    _load_openrouter_catalog()
    return _memory_cache or {}


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
    """Force a refresh of the model and pricing cache."""
    global _memory_cache, _memory_catalog
    _memory_cache = None
    _memory_catalog = None
    if CACHE_PATH.exists():
        CACHE_PATH.unlink()
    fresh = _fetch_openrouter_catalog()
    if fresh:
        _save_cache(fresh)
        _memory_catalog = fresh
        _memory_cache = _catalog_pricing(fresh)
        return True
    return False
