"""Scenario-macro aggregation for benchmark evaluation results.

The official aggregate must not be a micro-average over findings: a large
scenario would otherwise dominate a small or zero-GT control. Repeated runs are
first averaged within their scenario, then scenarios receive equal weight.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from statistics import fmean
from typing import Any

from src.benchmark.evaluator import EvaluationResult


EvaluationLike = EvaluationResult | Mapping[str, Any]


def _get(result: EvaluationLike, key: str, default: Any = None) -> Any:
    if isinstance(result, Mapping):
        return result.get(key, default)
    return getattr(result, key, default)


def _mean(values: Iterable[float]) -> float | None:
    materialized = list(values)
    return fmean(materialized) if materialized else None


def _round_optional(value: float | None, digits: int = 3) -> float | None:
    return round(value, digits) if value is not None else None


def _scenario_sort_key(scenario_id: str) -> tuple[int, str]:
    numeric = ""
    suffix = ""
    for char in scenario_id:
        if char.isdigit() and not suffix:
            numeric += char
        else:
            suffix += char
    return (int(numeric), suffix) if numeric else (10**9, scenario_id)


def _result_scenario_score(result: EvaluationLike, is_zero_gt: bool) -> float:
    score = _get(result, "scenario_score_pct")
    if score is not None:
        return float(score)
    if is_zero_gt:
        specificity = _get(result, "specificity")
        if specificity is None:
            specificity = 1.0 if int(_get(result, "false_positives", 0)) == 0 else 0.0
        return float(specificity) * 100.0
    return float(_get(result, "f1_score", 0.0)) * 100.0


def _summary_for_scenarios(scenarios: list[dict[str, Any]]) -> dict[str, Any]:
    positive = [s for s in scenarios if s["is_zero_gt"] is False]
    controls = [s for s in scenarios if s["is_zero_gt"] is True]
    return {
        "scenario_count": len(scenarios),
        "macro_scenario_score_pct": _round_optional(
            _mean(float(s["scenario_score_pct"]) for s in scenarios)
        ),
        "macro_positive_f1": _round_optional(
            _mean(float(s["f1_score"]) for s in positive)
        ),
        "macro_zero_gt_specificity": _round_optional(
            _mean(float(s["specificity"]) for s in controls)
        ),
    }


def aggregate_evaluations(
    evaluations: Iterable[EvaluationLike],
    *,
    expected_scenarios: Iterable[str | int] | None = None,
    scenario_splits: Mapping[str | int, str] | None = None,
) -> dict[str, Any]:
    """Aggregate evaluations with equal weight per scenario.

    Multiple seeds/runs for one scenario are averaged before the suite macro is
    computed. Scenarios listed in ``expected_scenarios`` but missing from the
    results are retained with a zero score so crashes cannot improve a batch.
    ``scenario_splits`` is intentionally supplied by the caller/evaluator-side
    manifest rather than inferred from agent-controlled run output.
    """
    rows = list(evaluations)
    split_map = {str(k): str(v) for k, v in (scenario_splits or {}).items()}
    grouped: dict[str, list[EvaluationLike]] = defaultdict(list)
    for row in rows:
        scenario_id = str(_get(row, "scenario_id", ""))
        if not scenario_id:
            raise ValueError("Evaluation result is missing scenario_id")
        grouped[scenario_id].append(row)

    expected = {str(s) for s in (expected_scenarios or [])}
    all_scenario_ids = set(grouped) | expected
    scenario_rows: list[dict[str, Any]] = []
    missing: list[str] = []

    for scenario_id in sorted(all_scenario_ids, key=_scenario_sort_key):
        runs = grouped.get(scenario_id, [])
        if not runs:
            missing.append(scenario_id)
            scenario_rows.append({
                "scenario_id": scenario_id,
                "split": split_map.get(scenario_id, "unassigned"),
                "run_count": 0,
                "missing": True,
                "is_zero_gt": None,
                "scenario_score_pct": 0.0,
                "f1_score": None,
                "specificity": None,
            })
            continue

        zero_gt_values = {bool(_get(run, "is_zero_gt", int(_get(run, "total_gt_vulns", 0)) == 0)) for run in runs}
        if len(zero_gt_values) != 1:
            raise ValueError(f"Scenario {scenario_id} mixes zero-GT and positive evaluations")
        is_zero_gt = zero_gt_values.pop()

        declared_splits = {
            str(value)
            for value in (_get(run, "split") for run in runs)
            if value not in (None, "")
        }
        if scenario_id in split_map:
            declared_splits.add(split_map[scenario_id])
        if len(declared_splits) > 1:
            raise ValueError(f"Scenario {scenario_id} has conflicting split metadata: {sorted(declared_splits)}")
        split = next(iter(declared_splits), "unassigned")

        scores = [_result_scenario_score(run, is_zero_gt) for run in runs]
        f1 = _mean(float(_get(run, "f1_score", 0.0)) for run in runs) if not is_zero_gt else None
        specificity = (
            _mean(
                float(
                    _get(run, "specificity")
                    if _get(run, "specificity") is not None
                    else (1.0 if int(_get(run, "false_positives", 0)) == 0 else 0.0)
                )
                for run in runs
            )
            if is_zero_gt
            else None
        )

        scenario_rows.append({
            "scenario_id": scenario_id,
            "split": split,
            "run_count": len(runs),
            "missing": False,
            "is_zero_gt": is_zero_gt,
            "scenario_score_pct": round(fmean(scores), 3),
            "f1_score": _round_optional(f1),
            "specificity": _round_optional(specificity),
        })

    suite_summary = _summary_for_scenarios(scenario_rows)
    per_split: dict[str, dict[str, Any]] = {}
    for split in sorted({s["split"] for s in scenario_rows}):
        split_scenarios = [s for s in scenario_rows if s["split"] == split]
        per_split[split] = _summary_for_scenarios(split_scenarios)

    return {
        "run_count": len(rows),
        **suite_summary,
        "missing_scenarios": missing,
        "per_scenario": {s["scenario_id"]: s for s in scenario_rows},
        "per_split": per_split,
    }


__all__ = ["aggregate_evaluations"]
