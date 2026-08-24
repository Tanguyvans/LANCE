"""Scenario-macro aggregation for benchmark evaluation results.

The official aggregate must not be a micro-average over findings: a large
scenario would otherwise dominate a small or zero-GT control. Repeated runs are
first averaged within their scenario, then scenarios receive equal weight.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from statistics import fmean, pstdev
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


def _complete_mean(values: Iterable[float | None]) -> float | None:
    """Average only when every expected value is comparable."""
    materialized = list(values)
    if not materialized or any(value is None for value in materialized):
        return None
    return fmean(float(value) for value in materialized if value is not None)


def _scenario_sort_key(scenario_id: str) -> tuple[int, str]:
    numeric = ""
    suffix = ""
    for char in scenario_id:
        if char.isdigit() and not suffix:
            numeric += char
        else:
            suffix += char
    return (int(numeric), suffix) if numeric else (10**9, scenario_id)


def _result_scenario_score(result: EvaluationLike, is_zero_gt: bool) -> float | None:
    score = _get(result, "scenario_score_pct")
    if score is not None:
        return float(score)
    if _get(result, "scoring_policy") == "strict-v3":
        return None
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
            _complete_mean(s.get("scenario_score_pct") for s in scenarios)
        ),
        "macro_positive_f1": _round_optional(
            _mean(float(s["f1_score"]) for s in positive)
        ),
        "macro_detection_f1": _round_optional(_mean(
            float(s["detection_f1"]) for s in positive
            if s.get("detection_f1") is not None
        )),
        "macro_quality_adjusted_f1": _round_optional(_mean(
            float(s["quality_adjusted_f1"]) for s in positive
            if s.get("quality_adjusted_f1") is not None
        )),
        "macro_verified_f1": _round_optional(_mean(
            float(s["verified_f1"]) for s in positive
            if s.get("verified_f1") is not None
        )),
        "macro_phase4_completion_rate": _round_optional(_mean(
            float(s["phase4_completion_rate"]) for s in positive
            if s.get("phase4_completion_rate") is not None
        )),
        "macro_quality_path_coverage": _round_optional(_mean(
            float(s["quality_path_coverage"]) for s in positive
            if s.get("quality_path_coverage") is not None
        )),
        "macro_verified_path_coverage": _round_optional(_mean(
            float(s["verified_path_coverage"]) for s in positive
            if s.get("verified_path_coverage") is not None
        )),
        **{
            f"macro_{name}": _round_optional(_mean(
                float(s[name]) for s in positive if s.get(name) is not None
            ))
            for name in (
                "phase5_target_attempt_coverage", "phase5_target_coverage",
                "phase5_compromise_rate", "phase5_hop_coverage",
                "phase5_pivot_success_rate", "phase5_chain_faithfulness",
            )
        },
        **{
            f"macro_{name}": _round_optional(_mean(
                float(s[name]) for s in positive if s.get(name) is not None
            ))
            for name in (
                "mhr_1", "mhr_2", "mhr_3",
                "mhr_1_credited", "mhr_2_credited", "mhr_3_credited",
                "mhr_1_verified", "mhr_2_verified", "mhr_3_verified",
            )
        },
        "macro_positive_precision": _round_optional(
            _mean(float(s["precision"]) for s in positive)
        ),
        "macro_positive_recall": _round_optional(
            _mean(float(s["recall"]) for s in positive)
        ),
        "macro_hallucination_rate": _round_optional(_mean(
            float(s["hallucination_rate"]) for s in positive
            if s.get("hallucination_rate") is not None
        )),
        **{
            f"macro_{name}": _round_optional(_mean(
                float(s[name]) for s in positive if s.get(name) is not None
            ))
            for name in (
                "critical_recall", "high_recall", "medium_recall", "low_recall",
                "phase3_device_completion_rate",
            )
        },
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
                "precision": None,
                "recall": None,
                "critical_recall": None,
                "high_recall": None,
                "medium_recall": None,
                "low_recall": None,
                "hallucination_rate": None,
                "phase3_device_completion_rate": None,
                "specificity": None,
                "detection_f1": None,
                "quality_adjusted_f1": None,
                "verified_f1": None,
                "phase4_completion_rate": None,
                "quality_path_coverage": None,
                "verified_path_coverage": None,
                "mhr_1": None,
                "mhr_2": None,
                "mhr_3": None,
                "mhr_1_credited": None,
                "mhr_2_credited": None,
                "mhr_3_credited": None,
                "mhr_1_verified": None,
                "mhr_2_verified": None,
                "mhr_3_verified": None,
                "run_score_stddev_pct": None,
                "phase5_target_attempt_coverage": None,
                "phase5_target_coverage": None,
                "phase5_compromise_rate": None,
                "phase5_hop_coverage": None,
                "phase5_pivot_success_rate": None,
                "phase5_chain_faithfulness": None,
                "phase5_targets_total": 0,
                "phase5_targets_attempted": 0,
                "phase5_targets_compromised": 0,
                "phase5_expected_hops": 0,
                "phase5_observed_hops": 0,
                "phase5_verified_hops": 0,
                "run_score_min_pct": None,
                "run_score_max_pct": None,
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

        run_scores = [_result_scenario_score(run, is_zero_gt) for run in runs]
        scores = [score for score in run_scores if score is not None]
        f1 = _mean(float(_get(run, "f1_score", 0.0)) for run in runs) if not is_zero_gt else None
        precision = _mean(float(_get(run, "precision", 0.0)) for run in runs) if not is_zero_gt else None
        recall = _mean(float(_get(run, "recall", 0.0)) for run in runs) if not is_zero_gt else None
        detection_f1 = _mean(
            float(_get(run, "detection_f1", _get(run, "f1_score", 0.0))) for run in runs
        ) if not is_zero_gt else None
        quality_values = [
            float(value) for value in (_get(run, "quality_adjusted_f1") for run in runs)
            if value is not None
        ]
        quality_adjusted_f1 = _mean(quality_values) if not is_zero_gt else None
        verified_values = [
            float(value) for value in (_get(run, "verified_f1") for run in runs)
            if value is not None
        ]
        completion_values = [
            float(value) for value in (_get(run, "phase4_completion_rate") for run in runs)
            if value is not None
        ]
        def optional_run_mean(name: str) -> float | None:
            return _mean(
                float(value) for value in (_get(run, name) for run in runs)
                if value is not None
            )
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
            "scenario_score_pct": _round_optional(_complete_mean(run_scores)),
            "f1_score": _round_optional(f1),
            "precision": _round_optional(precision),
            "recall": _round_optional(recall),
            "critical_recall": _round_optional(optional_run_mean("critical_recall")),
            "high_recall": _round_optional(optional_run_mean("high_recall")),
            "medium_recall": _round_optional(optional_run_mean("medium_recall")),
            "low_recall": _round_optional(optional_run_mean("low_recall")),
            "hallucination_rate": _round_optional(optional_run_mean("hallucination_rate")),
            "phase3_device_completion_rate": _round_optional(optional_run_mean("phase3_device_completion_rate")),
            "specificity": _round_optional(specificity),
            "detection_f1": _round_optional(detection_f1),
            "quality_adjusted_f1": _round_optional(quality_adjusted_f1),
            "verified_f1": _round_optional(_mean(verified_values)),
            "phase4_completion_rate": _round_optional(_mean(completion_values)),
            "quality_path_coverage": _round_optional(optional_run_mean("quality_path_coverage")),
            "verified_path_coverage": _round_optional(optional_run_mean("verified_path_coverage")),
            **{
                name: _round_optional(optional_run_mean(name))
                for name in (
                    "mhr_1", "mhr_2", "mhr_3",
                    "mhr_1_credited", "mhr_2_credited", "mhr_3_credited",
                    "mhr_1_verified", "mhr_2_verified", "mhr_3_verified",
                    "phase5_target_attempt_coverage", "phase5_target_coverage",
                    "phase5_compromise_rate", "phase5_hop_coverage",
                    "phase5_pivot_success_rate", "phase5_chain_faithfulness",
                )
            },
            "run_score_stddev_pct": (
                round(pstdev(scores), 3)
                if len(scores) > 1 and len(scores) == len(run_scores)
                else (0.0 if len(scores) == len(run_scores) == 1 else None)
            ),
            "run_score_min_pct": (
                round(min(scores), 3) if len(scores) == len(run_scores) else None
            ),
            "run_score_max_pct": (
                round(max(scores), 3) if len(scores) == len(run_scores) else None
            ),
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
