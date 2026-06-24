"""Providers API — CRUD over the LLM provider registry (SQLite ``providers``).

A provider holds the connection config (base_url, default_model) and the NAME
of the env var that carries its API key (``api_key_env``) — never the key
itself. Adding a ``kind='local'`` provider with a custom ``base_url`` is how a
local OpenAI-compatible endpoint (ollama / vLLM) gets wired in.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()


def _require_db():
    """Ensure the SQLite DB is reachable; raise 503 otherwise."""
    try:
        from src.db import database as db
        db.init_db()
        return db
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"Base de données indisponible : {exc}")


# api_key is intentionally absent — only the env-var NAME is stored.
class ProviderCreate(BaseModel):
    name: str
    base_url: str | None = None
    api_key_env: str | None = None
    default_model: str | None = None
    kind: str = "cloud"


class ProviderPatch(BaseModel):
    base_url: str | None = None
    api_key_env: str | None = None
    default_model: str | None = None
    kind: str | None = None


@router.get("")
def list_providers() -> dict:
    """Return all configured providers."""
    db = _require_db()
    return {"providers": db.list_providers()}


@router.post("")
def create_provider(body: ProviderCreate) -> dict:
    """Create (or upsert) a provider."""
    db = _require_db()
    db.upsert_provider(
        name=body.name, base_url=body.base_url, api_key_env=body.api_key_env,
        default_model=body.default_model, kind=body.kind or "cloud",
    )
    return db.get_provider(body.name)


@router.patch("/{name}")
def update_provider(name: str, body: ProviderPatch) -> dict:
    """Partially update an existing provider."""
    db = _require_db()
    existing = db.get_provider(name)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"Provider introuvable : {name}")
    merged = {**existing, **body.model_dump(exclude_unset=True)}
    db.upsert_provider(
        name=name, base_url=merged.get("base_url"), api_key_env=merged.get("api_key_env"),
        default_model=merged.get("default_model"), kind=merged.get("kind") or "cloud",
    )
    return db.get_provider(name)
