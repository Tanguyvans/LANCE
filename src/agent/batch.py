"""Batch runner — runs multiple benchmark scenarios sequentially and aggregates metrics."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[2]
GT_DIR = ROOT / "benchmarks" / "ground_truth"
OUTPUT_DIR = ROOT / "output" / "agent"


class SealedScenarioError(ValueError):
    """Raised when a local runner is asked to execute a sealed scenario."""


def _available_scenarios() -> list[str]:
    """Return deployable public scenarios, including legacy hardened variants."""
    from src.benchmark.catalog import DEV_PUBLIC, list_scenarios

    ids = [item.id for item in list_scenarios(DEV_PUBLIC)]
    variants = [
        path.stem.removeprefix("scenario_")
        for path in GT_DIR.glob("scenario_*.yaml")
        if not path.stem.removeprefix("scenario_").isdigit()
    ]

    def sort_key(value: str) -> tuple[int, str]:
        number = "".join(ch for ch in value if ch.isdigit())
        suffix = value[len(number):]
        return (int(number), suffix) if number else (10**9, value)

    return sorted(set(ids + variants), key=sort_key)


def _parse_scenario_ids(batch_arg: str) -> list[str]:
    """Parse --batch argument into a list of scenario ID strings.

    Examples:
        "1,2,3"  -> ["1", "2", "3"]
        "1,2h,4" -> ["1", "2h", "4"]
        "all"    -> all available scenario IDs sorted by filename
    """
    selector = batch_arg.strip().lower()
    if selector == "all":
        return _available_scenarios()
    from src.benchmark.catalog import CatalogError, load_catalog

    if selector not in {"dev", "dev-public", "eval", "eval-sealed"}:
        resolved: list[str] = []
        for raw in selector.split(","):
            sid = raw.strip().removeprefix("s")
            if not sid:
                continue
            if sid.isdigit():
                try:
                    descriptor = load_catalog().get(sid)
                except CatalogError as exc:
                    raise ValueError(str(exc)) from exc
                if descriptor.sealed:
                    raise SealedScenarioError(
                        f"S{sid} must run through the external sealed controller"
                    )
                resolved.append(descriptor.id)
            elif (GT_DIR / f"scenario_{sid}.yaml").exists():
                resolved.append(sid)
            else:
                raise ValueError(f"Unknown public scenario variant: S{sid}")
        if not resolved:
            raise ValueError(f"No valid scenario IDs found in --batch '{batch_arg}'")
        return list(dict.fromkeys(resolved))

    try:
        selected = load_catalog().resolve_selector(selector)
    except CatalogError as exc:
        raise ValueError(str(exc)) from exc
    sealed = [item.id for item in selected if item.sealed]
    if sealed:
        raise SealedScenarioError(
            "Sealed scenarios must run through the external controller: "
            + ", ".join(f"S{sid}" for sid in sealed)
        )
    return [item.id for item in selected]


def _parse_single_scenario_id(value: int | str) -> str:
    """Resolve one deployable public scenario, including hardened variants."""
    scenario_ids = _parse_scenario_ids(str(value))
    if len(scenario_ids) != 1:
        raise ValueError(
            f"Expected exactly one public scenario, got {len(scenario_ids)} from {value!r}"
        )
    return scenario_ids[0]


def _evaluation_metrics(evaluation: Any) -> dict[str, Any]:
    """Return stable per-run metrics with the strict-v2 scenario score as primary."""
    specificity = evaluation.specificity
    return {
        "recall": round(evaluation.recall, 3),
        "precision": round(evaluation.precision, 3),
        "f1": round(evaluation.f1_score, 3),
        "weighted_score": round(evaluation.weighted_score, 3),
        "max_weighted_score": evaluation.max_weighted_score,
        # strict-v2 scores positive scenarios by F1 and zero-GT controls by
        # specificity. Keep the legacy weighted percentage under an explicit
        # name so a clean control is not displayed as a 0% run.
        "score_pct": round(evaluation.scenario_score_pct, 1),
        "weighted_score_pct": round(evaluation.score_pct, 1),
        "scenario_score_pct": round(evaluation.scenario_score_pct, 1),
        "tp": evaluation.true_positives,
        "fp": evaluation.false_positives,
        "fn": evaluation.false_negatives,
        "exploitation_coverage": round(evaluation.exploitation_coverage, 3),
        "path_coverage": round(getattr(evaluation, "path_coverage", 0.0), 3),
        "attack_paths_detected": getattr(evaluation, "attack_paths_detected", 0),
        "total_attack_paths": getattr(evaluation, "total_attack_paths", 0),
        "specificity": round(specificity, 3) if specificity is not None else None,
        "is_zero_gt": evaluation.is_zero_gt,
        "scoring_policy": evaluation.scoring_policy,
    }


def _aggregate_batch_results(
    evaluations: Iterable[Any],
    results: list[dict[str, Any]],
    scenario_ids: Iterable[str],
) -> dict[str, Any]:
    """Build one aggregate schema for the CLI and dashboard batch runners."""
    expected = list(dict.fromkeys(str(sid) for sid in scenario_ids))
    if not expected:
        return {}

    from src.benchmark.aggregate import aggregate_evaluations

    completed = [result for result in results if result.get("metrics")]
    official = aggregate_evaluations(
        evaluations,
        expected_scenarios=expected,
        scenario_splits={sid: "dev-public" for sid in expected},
    )
    return {
        **official,
        "avg_recall": round(
            sum(result["metrics"]["recall"] for result in completed) / len(completed), 3
        ) if completed else 0.0,
        "avg_precision": round(
            sum(result["metrics"]["precision"] for result in completed) / len(completed), 3
        ) if completed else 0.0,
        "avg_f1": round(
            sum(result["metrics"]["f1"] for result in completed) / len(completed), 3
        ) if completed else 0.0,
        "avg_score_pct": official["macro_scenario_score_pct"],
        "total_cost_usd": round(sum(result.get("cost_usd", 0) for result in results), 4),
        "scenarios_evaluated": len(completed),
        "scenarios_skipped": len(expected) - len(completed),
    }


def run_batch(
    batch_arg: str,
    provider,
    dry_run: bool = False,
    phases: list[int] | None = None,
    blind: bool = False,
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
    evaluation_results = []

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

        pipeline = None
        try:
            pipeline = Pipeline(
                provider=provider,
                dry_run=dry_run,
                phases=phases,
                scenario_id=scenario_id,
                auto_teardown=True,
                blind=blind,
                benchmark_split="dev-public",
            )
            run_results = pipeline.run()
        except Exception as exc:
            failed_run_dir = getattr(pipeline, "run_dir", None)
            tracker = getattr(pipeline, "tracker", None)
            cost = round(tracker.total_cost(), 4) if tracker is not None else 0.0
            entry = {
                "scenario_id": sid,
                "run_dir": str(failed_run_dir) if failed_run_dir else None,
                "cost_usd": cost,
                "status": "failed",
                "reason": str(exc),
            }
            print(f"  [!] Pipeline failed: {exc}")
            results.append(entry)
            _print_scenario_summary(sid, entry)
            continue

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
            ev = evaluate(run_dir, gt_file, policy="strict-v2")
            ev.split = "dev-public"
            evaluation_results.append(ev)
            entry["metrics"] = _evaluation_metrics(ev)
        except Exception as exc:
            print(f"  [!] Evaluation failed: {exc}")
            entry["status"] = "evaluation_failed"
            entry["reason"] = str(exc)

        results.append(entry)
        _print_scenario_summary(sid, entry)

    aggregate = _aggregate_batch_results(evaluation_results, results, scenario_ids)

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
    elif entry.get("status") == "failed":
        print(f"  S{sid}: pipeline failed ({entry.get('reason', 'unknown error')}). Cost=${cost:.4f}")
    elif entry.get("status") == "evaluation_failed":
        print(f"  S{sid}: evaluation failed ({entry.get('reason', 'unknown error')}). Cost=${cost:.4f}")
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
            label = str(r.get("status", "skipped")).replace("_", " ").upper()
            print(f"  S{sid:<{col['s'] - 1}} {label:>{col['r']}}")
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
