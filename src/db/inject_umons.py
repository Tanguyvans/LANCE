#!/usr/bin/env python3
"""Register the UMONS Ollama provider and its models in the LANCE registry.

The ``ollama-umons`` provider and its models (``flint``, ``gemma4`` and
``qwen3.8``) live in each instance's SQLite registry, not in versioned code, so
a fresh registry — or a reseed — does not know about them. This script makes
that registration reproducible and idempotent, mirroring ``inject_moe.py``.

The endpoint is resolved without freezing an address in code: a ``--base-url``
flag wins, then ``LANCE_UMONS_BASE_URL``, then the URL already stored for the
``ollama-umons`` provider (so a re-run never clobbers a working deployment),
and only then the documented relay default. See ``docs/guides/umons-llm.md``.

Adding an entry here does not install the model on the UMONS server; the
administrator must make it available upstream.

Usage::

    LANCE_DB_PATH=/opt/lance-dev-2/data/lance.db \
        python3 -m src.db.inject_umons --base-url http://100.66.221.22:11435/v1
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Sequence

# Add project root to path so the module runs both as a script and via -m.
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.db.database import (  # noqa: E402
    get_conn,
    get_provider,
    init_db,
    upsert_model,
    upsert_provider,
)

PROVIDER_NAME = "ollama-umons"

# Documented relay default (see docs/guides/umons-llm.md). Overridable by
# --base-url, LANCE_UMONS_BASE_URL, or the value already in the registry, so no
# address is frozen in code: this is only the last-resort fallback.
DEFAULT_BASE_URL = "http://100.66.221.22:11435/v1"

# (slug, label, parameter_count_b, active_parameter_count_b), mirroring the
# reference instance. flint is a sparse MoE (≈40B total, ≈2.5B active); the
# other two leave the counts unset, exactly as registered on the reference.
MODELS: tuple[tuple[str, str, float | None, float | None], ...] = (
    ("flint:latest", "flint (Recursive 40B MoE)", 39.8, 2.5),
    ("gemma4:26b-a4b-it-q4_K_M", "Gemma 4 26B A4B — UMONS", None, None),
    ("qwen3.8:27b", "Qwen 3.8 27B — UMONS", None, None),
)

# The model selected by default when the provider is chosen.
DEFAULT_MODEL = "qwen3.8:27b"


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url",
        default=None,
        help=(
            "OpenAI-compatible UMONS relay URL. When omitted, use "
            "LANCE_UMONS_BASE_URL, then the existing ollama-umons registry "
            f"URL, then {DEFAULT_BASE_URL}."
        ),
    )
    return parser.parse_args(argv)


def resolve_base_url(cli_value: str | None) -> str:
    """Resolve the endpoint without overwriting a deployed registry by accident."""
    candidate = cli_value or os.environ.get("LANCE_UMONS_BASE_URL")
    if not candidate:
        row = get_provider(PROVIDER_NAME)
        candidate = row["base_url"] if row and row.get("base_url") else DEFAULT_BASE_URL
    return candidate.rstrip("/")


def main(argv: Sequence[str] | None = None) -> None:
    args = parse_args(argv)
    init_db()
    base_url = resolve_base_url(args.base_url)

    # No API key: the relay is an unauthenticated local endpoint, so the
    # selector must not gate availability on a key env var.
    upsert_provider(
        name=PROVIDER_NAME,
        base_url=base_url,
        api_key_env=None,
        default_model=DEFAULT_MODEL,
        kind="local",
        request_mode="sequential",
    )

    for slug, label, total_b, active_b in MODELS:
        upsert_model(
            slug=slug,
            label=label,
            provider=PROVIDER_NAME,
            recommended=False,
            enabled=True,
            subscription=False,
            parameter_count_b=total_b,
            active_parameter_count_b=active_b,
            profile_policy="auto",
        )

    with get_conn() as conn:
        rows = conn.execute(
            "SELECT slug FROM models WHERE provider = ? ORDER BY slug",
            (PROVIDER_NAME,),
        ).fetchall()
    registered = [row["slug"] for row in rows]
    print(
        f"Registered provider '{PROVIDER_NAME}' ({base_url}) "
        f"with models: {', '.join(registered)}"
    )


if __name__ == "__main__":
    main()
