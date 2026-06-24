"""Allow running as: python3 -m src.agent"""
from __future__ import annotations

import argparse
import logging
import os

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
        default=os.environ.get("AGENT_PROVIDER", "anthropic"),
        choices=["anthropic", "openrouter", "minimax", "glm", "qwen", "local"],
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("AGENT_MODEL"),
    )
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
    parser.add_argument(
        "--scenario",
        type=int,
        default=None,
        help="Benchmark scenario ID (1-10). Loads VM IPs from ground_truth/scenario_N.yaml.",
    )
    parser.add_argument(
        "--batch",
        default=None,
        metavar="IDS",
        help=(
            "Run multiple scenarios sequentially and aggregate metrics. "
            "Accepts comma-separated IDs (e.g. '1,2,3') or 'all'."
        ),
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    provider = LLMProvider(provider=args.provider, model=args.model)

    # Batch mode: sequential multi-scenario run
    if args.batch is not None:
        from src.agent.batch import run_batch
        run_batch(
            batch_arg=args.batch,
            provider=provider,
            dry_run=args.dry_run,
            phases=args.phases,
        )
        return

    pipeline = Pipeline(
        provider=provider, dry_run=args.dry_run, phases=args.phases,
        scenario_id=args.scenario,
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
