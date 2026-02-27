"""Allow running as: python3 -m src.agent"""
from __future__ import annotations

import argparse
import logging

from dotenv import load_dotenv

load_dotenv()

from src.agent.provider import LLMProvider
from src.agent.pipeline import Pipeline


def main():
    parser = argparse.ArgumentParser(
        description="NATO Smart City IoT — Pentest Agent Pipeline"
    )
    parser.add_argument(
        "--provider",
        default="anthropic",
        choices=["anthropic", "openrouter"],
    )
    parser.add_argument("--model", default=None)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Graph tools only, no network recon tools",
    )
    parser.add_argument(
        "--phases",
        nargs="+",
        type=int,
        help="Run specific phases only (e.g. --phases 1 2)",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    provider = LLMProvider(provider=args.provider, model=args.model)
    pipeline = Pipeline(
        provider=provider, dry_run=args.dry_run, phases=args.phases
    )
    results = pipeline.run()

    print(f"\n{'=' * 60}")
    print("PIPELINE COMPLETE")
    print(f"{'=' * 60}")
    for name, status in results.items():
        icon = "v" if status == "completed" else "x" if "failed" in status else "-"
        print(f"  [{icon}] {name}: {status}")


if __name__ == "__main__":
    main()
