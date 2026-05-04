"""Compare baseline runs against benchmark ground truth."""
from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict
from pathlib import Path

from src.benchmark.evaluator import evaluate


GT_DIR = Path("benchmarks/ground_truth")


def scenario_from_run_dir(run_dir: Path) -> str:
    metadata = run_dir / "metadata.json"
    if metadata.exists():
        data = json.loads(metadata.read_text(encoding="utf-8"))
        if data.get("scenario_id"):
            return str(data["scenario_id"])
    match = re.search(r"S([^_/]+)", run_dir.name)
    if match:
        return match.group(1)
    raise ValueError(f"Cannot infer scenario id from {run_dir}")


def evaluate_baseline_run(run_dir: Path, ground_truth_dir: Path = GT_DIR) -> dict:
    scenario_id = scenario_from_run_dir(run_dir)
    gt_file = ground_truth_dir / f"scenario_{scenario_id}.yaml"
    result = evaluate(run_dir, gt_file)
    return asdict(result)


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate one or more baseline run directories")
    parser.add_argument("run_dirs", nargs="+", type=Path)
    parser.add_argument("--ground-truth-dir", type=Path, default=GT_DIR)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    results = []
    for run_dir in args.run_dirs:
        result = evaluate_baseline_run(run_dir, args.ground_truth_dir)
        results.append(result)
        print(
            f"S{result['scenario_id']} {run_dir}: "
            f"Recall={result['recall']:.3f} Precision={result['precision']:.3f} "
            f"F1={result['f1_score']:.3f} Score={result['score_pct']:.1f}%"
        )

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    main()

