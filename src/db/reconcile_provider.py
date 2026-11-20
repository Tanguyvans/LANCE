#!/usr/bin/env python3
"""Reconcile the LLM provider in the LANCE registry from the environment.

Run at container start (see ``docker/entrypoint.sh``) so the ``.env`` is the
single source of truth for the LLM endpoint: no manual ``inject_*`` step, and no
stale ``providers`` row silently overriding a changed ``.env``. It is idempotent
and a no-op when the variables are unset, so existing deployments are untouched.

Environment:
  AGENT_PROVIDER      provider name to upsert (e.g. ``ollama-umons``)
  LANCE_MOE_BASE_URL  OpenAI-compatible endpoint (e.g. ``http://localhost:11434/v1``)
  LANCE_MOE_MODEL     served model slug to register and set as default (optional)
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Add project root to path when run as a script.
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.db.database import get_conn, get_provider, init_db, upsert_model, upsert_provider


def reconcile_from_env() -> str | None:
    """Upsert the provider (and its model) from the environment.

    Returns the provider name when something was reconciled, else ``None``.
    """
    provider = (os.environ.get("AGENT_PROVIDER") or "").strip()
    base_url = (os.environ.get("LANCE_MOE_BASE_URL") or "").strip().rstrip("/")
    model = (os.environ.get("LANCE_MOE_MODEL") or "").strip()

    # Nothing to do unless both the provider name and its endpoint are given.
    if not provider or not base_url:
        return None

    if not base_url.startswith(("http://", "https://")):
        print(
            f"[reconcile] WARNING: LANCE_MOE_BASE_URL has no http(s) scheme: {base_url!r}",
            file=sys.stderr,
        )

    init_db()

    # Guard: AGENT_PROVIDER is also the cloud provider-selection var. Never clobber
    # a non-local row (e.g. 'minimax' with its MINIMAX_API_KEY binding) and silently
    # drop its auth — skip and warn instead.
    existing = get_provider(provider)
    if existing and (existing.get("kind") or "local") != "local":
        print(
            f"[reconcile] WARNING: provider '{provider}' already exists as "
            f"kind='{existing.get('kind')}'; skipping to avoid dropping its auth. "
            "Use a dedicated local provider name.",
            file=sys.stderr,
        )
        return None

    upsert_provider(
        name=provider,
        base_url=base_url,
        api_key_env=None,        # local OpenAI-compatible endpoint needs no key
        default_model=model or None,
        kind="local",
    )
    if model:
        # Register the served model so it appears in the dashboard selector.
        upsert_model(
            slug=model,
            label=model,
            provider=provider,
            recommended=True,
            enabled=True,
        )
        # Make it the SOLE recommended model so the dashboard auto-selects it
        # (the selector takes the first recommended row by slug order); otherwise
        # a stale recommended row from a prior inject/seed could win alphabetically.
        with get_conn() as conn:
            conn.execute("UPDATE models SET recommended = 0 WHERE slug != ?", (model,))
    return provider


def main() -> None:
    provider = reconcile_from_env()
    if provider is None:
        print(
            "[reconcile] AGENT_PROVIDER / LANCE_MOE_BASE_URL unset — "
            "leaving the provider registry unchanged."
        )
        return
    model = (os.environ.get("LANCE_MOE_MODEL") or "").strip()
    base_url = (os.environ.get("LANCE_MOE_BASE_URL") or "").strip().rstrip("/")
    print(
        f"[reconcile] provider '{provider}' -> {base_url}"
        + (f" (model '{model}')" if model else "")
    )


if __name__ == "__main__":
    main()
