"""Batch runner — runs multiple benchmark scenarios sequentially and aggregates metrics."""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

GT_DIR = Path("benchmarks/ground_truth")
OUTPUT_DIR = Path("output/agent")


def _available_scenarios() -> list[str]:
    """Return sorted list of available scenario IDs (e.g. ['1', '1h', '2', ...])."""
    ids = []
    for p in sorted(GT_DIR.glob("scenario_*.yaml"), key=lambda p: p.name):
        m = re.match(r"scenario_(.+)\.yaml$", p.name)
        if m:
            ids.append(m.group(1))
    return ids


def _parse_scenario_ids(batch_arg: str) -> list[str]:
    """Parse --batch argument into a list of scenario ID strings.

    Examples:
        "1,2,3"  -> ["1", "2", "3"]
        "1,2h,4" -> ["1", "2h", "4"]
        "all"    -> all available scenario IDs sorted by filename
    """
    if batch_arg.strip().lower() == "all":
        return _available_scenarios()
    return [s.strip() for s in batch_arg.split(",") if s.strip()]


def run_batch(
    batch_arg: str,
    provider,
    dry_run: bool = False,
    phases: list[int] | None = None,
) -> Path:
    """Run scenarios sequentially and save batch_summary.json.

    Returns the path to the batch summary JSON file.
    """
    from src.agent.pipeline import Pipeline
    from src.benchmark.evaluator import evaluate

    scenario_ids = _parse_scenario_ids(batch_arg)
    if not scenario_ids:
        raise ValueError(f"No valid scenario IDs found in --batch '{batch_arg}'")

    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    batch_dir = OUTPUT_DIR / f"batch_{timestamp}"
    batch_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'=' * 60}")
    print(f"BATCH RUN — {len(scenario_ids)} scenario(s): {', '.join(f'S{s}' for s in scenario_ids)}")
    print(f"Model : {getattr(provider, 'model', 'unknown')}")
    print(f"Output: {batch_dir}")
    print(f"{'=' * 60}\n")

    results: list[dict] = []

    for idx, sid in enumerate(scenario_ids, 1):
        scenario_id: int | str = int(sid) if sid.isdigit() else sid
        gt_file = GT_DIR / f"scenario_{sid}.yaml"

        if not gt_file.exists():
            print(f"[{idx}/{len(scenario_ids)}] S{sid} — SKIPPED (ground truth not found: {gt_file})")
            results.append({
                "scenario_id": sid,
                "status": "skipped",
                "reason": "no ground truth file",
            })
            continue

        print(f"[{idx}/{len(scenario_ids)}] Running S{sid}...")

        pipeline = Pipeline(
            provider=provider,
            dry_run=dry_run,
            phases=phases,
            scenario_id=scenario_id,
            auto_teardown=True,
        )

        run_results = pipeline.run()
        run_dir = pipeline.run_dir
        cost = round(pipeline.tracker.total_cost(), 4)

        entry: dict = {
            "scenario_id": sid,
            "run_dir": str(run_dir),
            "pipeline_results": run_results,
            "cost_usd": cost,
            "status": "ok",
        }

        try:
            ev = evaluate(run_dir, gt_file)
            entry["metrics"] = {
                "recall": round(ev.recall, 3),
                "precision": round(ev.precision, 3),
                "f1": round(ev.f1_score, 3),
                "weighted_score": round(ev.weighted_score, 3),
                "max_weighted_score": ev.max_weighted_score,
                "score_pct": round(ev.score_pct, 1),
                "tp": ev.true_positives,
                "fp": ev.false_positives,
                "fn": ev.false_negatives,
                "exploitation_coverage": round(ev.exploitation_coverage, 3),
            }
        except Exception as exc:
            print(f"  [!] Evaluation failed: {exc}")

        results.append(entry)
        _print_scenario_summary(sid, entry)

    completed = [r for r in results if r.get("status") == "ok" and "metrics" in r]
    aggregate: dict = {}
    if completed:
        aggregate = {
            "avg_recall": round(sum(r["metrics"]["recall"] for r in completed) / len(completed), 3),
            "avg_precision": round(sum(r["metrics"]["precision"] for r in completed) / len(completed), 3),
            "avg_f1": round(sum(r["metrics"]["f1"] for r in completed) / len(completed), 3),
            "avg_score_pct": round(sum(r["metrics"]["score_pct"] for r in completed) / len(completed), 1),
            "total_cost_usd": round(sum(r.get("cost_usd", 0) for r in results), 4),
            "scenarios_evaluated": len(completed),
            "scenarios_skipped": len(results) - len(completed),
        }

    summary = {
        "batch_timestamp": timestamp,
        "model": getattr(provider, "model", None),
        "scenarios": results,
        "aggregate": aggregate,
    }

    summary_path = batch_dir / "batch_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False))

    _print_batch_table(results, aggregate, summary_path)
    return summary_path


def _print_scenario_summary(sid: str, entry: dict) -> None:
    m = entry.get("metrics")
    cost = entry.get("cost_usd", 0)
    if m:
        print(
            f"  S{sid}: Recall={m['recall']:.3f}  Precision={m['precision']:.3f}  "
            f"F1={m['f1']:.3f}  Score={m['score_pct']:.1f}%  "
            f"TP={m['tp']}  FP={m['fp']}  FN={m['fn']}  Cost=${cost:.4f}"
        )
    else:
        print(f"  S{sid}: pipeline done, evaluation unavailable. Cost=${cost:.4f}")


def _print_batch_table(results: list[dict], aggregate: dict, summary_path: Path) -> None:
    col = {"s": 10, "r": 8, "p": 10, "f1": 7, "sc": 8, "tp": 5, "fp": 5, "fn": 5, "cost": 10}
    header = (
        f"  {'Scenario':<{col['s']}} {'Recall':>{col['r']}} {'Precision':>{col['p']}} "
        f"{'F1':>{col['f1']}} {'Score%':>{col['sc']}} "
        f"{'TP':>{col['tp']}} {'FP':>{col['fp']}} {'FN':>{col['fn']}} {'Cost':>{col['cost']}}"
    )
    sep = "  " + "-" * (len(header) - 2)

    print(f"\n{'=' * 60}")
    print("BATCH COMPLETE")
    print(f"{'=' * 60}")
    print(header)
    print(sep)

    for r in results:
        sid = r["scenario_id"]
        if r.get("status") != "ok" or "metrics" not in r:
            print(f"  S{sid:<{col['s'] - 1}} {'SKIPPED':>{col['r']}}")
            continue
        m = r["metrics"]
        print(
            f"  S{sid:<{col['s'] - 1}} {m['recall']:>{col['r']}.3f} {m['precision']:>{col['p']}.3f} "
            f"{m['f1']:>{col['f1']}.3f} {m['score_pct']:>{col['sc']}.1f} "
            f"{m['tp']:>{col['tp']}} {m['fp']:>{col['fp']}} {m['fn']:>{col['fn']}} "
            f"${r['cost_usd']:>{col['cost'] - 1}.4f}"
        )

    if aggregate:
        print(sep)
        print(
            f"  {'AVERAGE':<{col['s'] - 1}} {aggregate['avg_recall']:>{col['r']}.3f} "
            f"{aggregate['avg_precision']:>{col['p']}.3f} {aggregate['avg_f1']:>{col['f1']}.3f} "
            f"{aggregate['avg_score_pct']:>{col['sc']}.1f}"
            f"{'':>{col['tp'] + col['fp'] + col['fn'] + 3}} "
            f"${aggregate['total_cost_usd']:>{col['cost'] - 1}.4f}"
        )

    print(f"\nSummary: {summary_path}")
