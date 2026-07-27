#!/usr/bin/env python3
"""Inject HMoE configuration into the LANCE SQLite registry."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Sequence

# Add project root to path
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.db.database import init_db, get_conn


def upsert_provider(name: str, base_url: str, api_key_env: str, default_model: str, kind: str = "local") -> None:
    query = """
        INSERT INTO providers (name, base_url, api_key_env, default_model, kind)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
            base_url = excluded.base_url,
            api_key_env = excluded.api_key_env,
            default_model = excluded.default_model,
            kind = excluded.kind
    """
    with get_conn() as conn:
        conn.execute(query, (name, base_url, api_key_env, default_model, kind))

def upsert_model(
    slug: str,
    label: str,
    provider: str,
    recommended: bool = False,
    enabled: bool = True,
    subscription: bool = False,
    parameter_count_b: float | None = None,
    active_parameter_count_b: float | None = None,
    profile_policy: str = "auto",
) -> None:
    query = """
        INSERT INTO models (slug, label, provider, recommended, enabled, subscription,
                            parameter_count_b, active_parameter_count_b, profile_policy)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(slug) DO UPDATE SET
            label = excluded.label,
            provider = excluded.provider,
            recommended = excluded.recommended,
            enabled = excluded.enabled,
            subscription = excluded.subscription,
            parameter_count_b = excluded.parameter_count_b,
            active_parameter_count_b = excluded.active_parameter_count_b,
            profile_policy = excluded.profile_policy
    """
    with get_conn() as conn:
        conn.execute(
            query,
            (slug, label, provider, int(recommended), int(enabled), int(subscription),
             parameter_count_b, active_parameter_count_b, profile_policy),
        )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url",
        default=os.environ.get("LANCE_MOE_BASE_URL", "http://localhost:8001/v1"),
        help="OpenAI-compatible HMoE API URL (default: %(default)s)",
    )
    parser.add_argument(
        "--include-experts",
        action="store_true",
        help="Also expose the four direct expert model IDs in the LANCE dashboard",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> None:
    args = parse_args(argv)
    init_db()

    upsert_provider(
        name="local-moe",
        base_url=args.base_url.rstrip("/"),
        api_key_env="LOCAL_API_KEY",
        default_model="lance-moe",
        kind="local"
    )

    upsert_model(
        "lance-moe", "LANCE HMoE (Auto-Router)", "local-moe", True, True,
        active_parameter_count_b=3.0,
    )
    if args.include_experts:
        upsert_model(
            "expert-recon", "Expert (Recon)", "local-moe", False, True,
            parameter_count_b=3.0,
        )
        upsert_model(
            "expert-vuln", "Expert (Vuln)", "local-moe", False, True,
            parameter_count_b=3.0,
        )
        upsert_model(
            "expert-exploit", "Expert (Exploit)", "local-moe", False, True,
            parameter_count_b=3.0,
        )
        upsert_model(
            "expert-secretary", "Expert (Secretary)", "local-moe", False, True,
            parameter_count_b=3.0,
        )

    print(
        "Successfully injected 'local-moe' provider and HMoE model(s) "
        f"using {args.base_url.rstrip('/')}"
    )


if __name__ == "__main__":
    main()
