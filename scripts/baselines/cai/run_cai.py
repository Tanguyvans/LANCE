"""Compatibility CLI for the CAI baseline.

The implementation lives in `src.baselines.runner`; this module preserves the
command shape documented in `paper/plan_cai_comparison.md`.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from src.baselines.runner import run_baseline


def main() -> None:
    parser = argparse.ArgumentParser(description="Run CAI baseline variant A or B")
    parser.add_argument("--variant", required=True, choices=["A", "B"])
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--target", default=None, help="Accepted for plan compatibility; orchestration uses GT target list")
    parser.add_argument("--scope", default="192.168.100.0/24")
    parser.add_argument("--max-turns", type=int, default=200)
    parser.add_argument("--model", default="MiniMax-M2.7")
    parser.add_argument("--output-dir", type=Path, default=Path("output/baselines"))
    parser.add_argument("--baseline-host", default="baseline", help="SSH host for the isolated baseline VM")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    run_dir = run_baseline(
        tool="cai",
        scenario_id=args.scenario,
        baseline_host=args.baseline_host,
        variant=args.variant,
        scope=args.scope,
        max_turns=args.max_turns,
        model=args.model,
        output_dir=args.output_dir,
        dry_run=args.dry_run,
    )
    print(run_dir)


if __name__ == "__main__":
    main()

