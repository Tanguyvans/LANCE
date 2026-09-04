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
        choices=["anthropic", "codex", "openrouter", "minimax", "glm", "qwen", "local"],
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("AGENT_MODEL"),
    )
    parser.add_argument(
        "--execution-profile",
        choices=["auto", "compact", "full"],
        default=os.environ.get("AGENT_EXECUTION_PROFILE", "auto"),
        help="Tool orchestration profile (default: auto).",
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
        type=str,
        default=None,
        help="Benchmark scenario ID. S1-S19 are public development scenarios; S20-S25 require the sealed controller.",
    )
    parser.add_argument(
        "--batch",
        default=None,
        metavar="IDS",
        help=(
            "Run multiple scenarios sequentially and aggregate metrics. "
            "Accepts comma-separated IDs, 'dev', or 'all'; eval requires the sealed controller."
        ),
    )
    parser.add_argument(
        "--blind",
        action="store_true",
        help="Hide the public topology and force active discovery.",
    )
    parser.add_argument(
        "--target-network",
        default=None,
        metavar="CIDR",
        help="Discovery scope, for example 192.168.100.0/24.",
    )
    parser.add_argument(
        "--split",
        choices=["auto", "dev-public", "eval-sealed"],
        default="auto",
        help="Benchmark split policy. Sealed runs must be launched by the controller worker.",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    resolved_split = None if args.split == "auto" else args.split
    if args.scenario is not None and args.batch is not None:
        parser.error("--scenario and --batch are mutually exclusive")
    if args.batch is not None and args.target_network is not None:
        parser.error("--target-network cannot be combined with --batch")
    if args.split == "eval-sealed":
        parser.error(
            "eval-sealed runs must be launched through the sealed controller; "
            "the regular CLI has no oracle or deployment access"
        )

    normalized_batch: str | None = None
    if args.batch is not None:
        from src.agent.batch import _parse_scenario_ids
        try:
            normalized_batch = ",".join(_parse_scenario_ids(args.batch))
        except ValueError as exc:
            parser.error(str(exc))
        resolved_split = "dev-public"
    elif args.scenario is not None:
        from src.agent.batch import _parse_single_scenario_id
        try:
            args.scenario = _parse_single_scenario_id(args.scenario)
        except ValueError as exc:
            parser.error(str(exc))
        if resolved_split not in (None, "dev-public"):
            parser.error(f"S{args.scenario} belongs to dev-public, not {resolved_split}")
        resolved_split = "dev-public"

    # Resolve all local-only validation before constructing a provider. This
    # keeps invalid/sealed invocations free of credentials and network setup.
    provider = LLMProvider(provider=args.provider, model=args.model)

    # Batch mode: sequential multi-scenario run
    if args.batch is not None:
        from src.agent.batch import run_batch
        run_batch(
            batch_arg=normalized_batch or args.batch,
            provider=provider,
            dry_run=args.dry_run,
            phases=args.phases,
            blind=args.blind,
            execution_profile=args.execution_profile,
        )
        return

    pipeline = Pipeline(
        provider=provider, dry_run=args.dry_run, phases=args.phases,
        scenario_id=args.scenario,
        blind=args.blind,
        target_network=args.target_network,
        benchmark_split=resolved_split,
        execution_profile=args.execution_profile,
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
