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
        "positive_scenario_count": len(positive),
        "control_scenario_count": len(controls),
        "macro_scenario_score_pct": _round_optional(
            _complete_mean(s.get("scenario_score_pct") for s in positive)
        ),
        "macro_positive_f1": _round_optional(
            _complete_mean(s.get("f1_score") for s in positive)
        ),
        "macro_detection_f1": _round_optional(_complete_mean(
            s.get("detection_f1") for s in positive
        )),
        "macro_quality_adjusted_f1": _round_optional(_complete_mean(
            s.get("quality_adjusted_f1") for s in positive
        )),
        "macro_verified_f1": _round_optional(_complete_mean(
            s.get("verified_f1") for s in positive
        )),
        "macro_verified_severity_coverage": _round_optional(_complete_mean(
            s.get("verified_severity_coverage") for s in positive
        )),
        "macro_negative_control_specificity": _round_optional(_mean(
            float(s["negative_control_specificity"])
            for s in positive if s.get("negative_control_specificity") is not None
        )),
        "macro_negative_control_clean_run_rate": _round_optional(_mean(
            float(s["negative_control_clean_run_rate"])
            for s in positive if s.get("negative_control_clean_run_rate") is not None
        )),
        "negative_control_scenario_count": sum(
            s.get("negative_control_clean_run_rate") is not None for s in positive
        ),
        "negative_control_run_count": sum(
            int(s.get("negative_control_run_count", 0)) for s in positive
        ),
        "macro_phase4_completion_rate": _round_optional(_complete_mean(
            s.get("phase4_completion_rate") for s in positive
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
                "mhr_1", "mhr_2", "mhr_3",
                "mhr_1_credited", "mhr_2_credited", "mhr_3_credited",
                "mhr_1_verified", "mhr_2_verified", "mhr_3_verified",
                "dhr_1", "dhr_2", "dhr_3",
                "dhr_1_verified", "dhr_2_verified", "dhr_3_verified",
            )
        },
        "macro_positive_precision": _round_optional(
            _complete_mean(s.get("precision") for s in positive)
        ),
        "macro_positive_recall": _round_optional(
            _complete_mean(s.get("recall") for s in positive)
        ),
        "macro_zero_gt_specificity": _round_optional(
            _complete_mean(s.get("specificity") for s in controls)
        ),
        "macro_zero_gt_clean_run_rate": _round_optional(
            _complete_mean(s.get("specificity") for s in controls)
        ),
    }


def aggregate_evaluations(
    evaluations: Iterable[EvaluationLike],
    *,
    expected_scenarios: Iterable[str | int] | None = None,
    expected_repetitions: int | Mapping[str | int, int] | None = None,
    scenario_is_zero_gt: Mapping[str | int, bool] | None = None,
    scenario_splits: Mapping[str | int, str] | None = None,
) -> dict[str, Any]:
    """Aggregate evaluations with equal weight per scenario.

    Multiple seeds/runs for one scenario are averaged before the suite macro is
    computed. ``expected_repetitions`` freezes the planned seed count; missing
    cells receive zero on official metrics so crashes cannot improve a batch.
    Zero-GT controls are reported as a separate clean-run rate and never mixed
    into the positive-scenario primary score.
    ``scenario_splits`` is intentionally supplied by the caller/evaluator-side
    manifest rather than inferred from agent-controlled run output.
    """
    rows = list(evaluations)
    split_map = {str(k): str(v) for k, v in (scenario_splits or {}).items()}
    zero_gt_map = {str(k): bool(v) for k, v in (scenario_is_zero_gt or {}).items()}
    grouped: dict[str, list[EvaluationLike]] = defaultdict(list)
    for row in rows:
        scenario_id = str(_get(row, "scenario_id", ""))
        if not scenario_id:
            raise ValueError("Evaluation result is missing scenario_id")
        grouped[scenario_id].append(row)

    expected = {str(s) for s in (expected_scenarios or [])}
    if isinstance(expected_repetitions, bool):
        raise ValueError("expected_repetitions must be a positive integer or mapping")
    if isinstance(expected_repetitions, int):
        if expected_repetitions <= 0:
            raise ValueError("expected_repetitions must be positive")
        repetition_map = {
            scenario_id: expected_repetitions
            for scenario_id in (expected or set(grouped))
        }
    else:
        repetition_map = {
            str(scenario_id): int(count)
            for scenario_id, count in (expected_repetitions or {}).items()
        }
        if any(count <= 0 for count in repetition_map.values()):
            raise ValueError("expected repetition counts must be positive")
        expected |= set(repetition_map)
    all_scenario_ids = set(grouped) | expected
    scenario_rows: list[dict[str, Any]] = []
    missing: list[str] = []

    for scenario_id in sorted(all_scenario_ids, key=_scenario_sort_key):
        runs = grouped.get(scenario_id, [])
        planned_run_count = repetition_map.get(
            scenario_id,
            max(1, len(runs)) if scenario_id in expected else len(runs),
        )
        if len(runs) > planned_run_count:
            raise ValueError(
                f"Scenario {scenario_id} has {len(runs)} results for "
                f"{planned_run_count} planned repetitions"
            )
        missing_run_count = planned_run_count - len(runs)
        if not runs:
            missing.append(scenario_id)
            is_zero_gt = zero_gt_map.get(scenario_id, False)
            scenario_rows.append({
                "scenario_id": scenario_id,
                "split": split_map.get(scenario_id, "unassigned"),
                "run_count": 0,
                "planned_run_count": planned_run_count,
                "completed_run_count": 0,
                "missing_run_count": missing_run_count,
                "completion_rate": 0.0,
                "missing": True,
                "is_zero_gt": is_zero_gt,
                "scenario_score_pct": 0.0,
                "f1_score": None if is_zero_gt else 0.0,
                "precision": None if is_zero_gt else 0.0,
                "recall": None if is_zero_gt else 0.0,
                "specificity": 0.0 if is_zero_gt else None,
                "detection_f1": None if is_zero_gt else 0.0,
                "quality_adjusted_f1": None if is_zero_gt else 0.0,
                "verified_f1": None if is_zero_gt else 0.0,
                "verified_severity_coverage": None if is_zero_gt else 0.0,
                # A missing official cell must not improve the published
                # control result. Confirmatory profiles all declare controls.
                "negative_control_specificity": None if is_zero_gt else 0.0,
                "negative_control_clean_run_rate": None if is_zero_gt else 0.0,
                "phase4_completion_rate": None if is_zero_gt else 0.0,
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
                "dhr_1": None,
                "dhr_2": None,
                "dhr_3": None,
                "dhr_1_verified": None,
                "dhr_2_verified": None,
                "dhr_3_verified": None,
                "run_score_stddev_pct": None,
                "run_score_min_pct": None,
                "run_score_max_pct": None,
            })
            continue

        zero_gt_values = {bool(_get(run, "is_zero_gt", int(_get(run, "total_gt_vulns", 0)) == 0)) for run in runs}
        if len(zero_gt_values) != 1:
            raise ValueError(f"Scenario {scenario_id} mixes zero-GT and positive evaluations")
        is_zero_gt = zero_gt_values.pop()
        if scenario_id in zero_gt_map and zero_gt_map[scenario_id] != is_zero_gt:
            raise ValueError(
                f"Scenario {scenario_id} conflicts with evaluator-side zero-GT metadata"
            )

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

        zero_fill = [0.0] * missing_run_count
        run_scores = [
            *[_result_scenario_score(run, is_zero_gt) for run in runs],
            *zero_fill,
        ]
        scores = [score for score in run_scores if score is not None]
        def completed_metric_values(name: str, *, default: Any = None) -> list[float | None]:
            return [
                float(value) if value is not None else None
                for value in (_get(run, name, default) for run in runs)
            ]

        f1 = _complete_mean([
            *completed_metric_values("f1_score", default=0.0), *zero_fill,
        ]) if not is_zero_gt else None
        precision = _complete_mean([
            *completed_metric_values("precision", default=0.0), *zero_fill,
        ]) if not is_zero_gt else None
        recall = _complete_mean([
            *completed_metric_values("recall", default=0.0), *zero_fill,
        ]) if not is_zero_gt else None
        detection_f1 = _complete_mean([
            *[
                float(_get(run, "detection_f1", _get(run, "f1_score", 0.0)))
                for run in runs
            ],
            *zero_fill,
        ]) if not is_zero_gt else None
        quality_adjusted_f1 = _complete_mean([
            *completed_metric_values("quality_adjusted_f1"), *zero_fill,
        ]) if not is_zero_gt else None
        verified_f1 = _complete_mean([
            *completed_metric_values("verified_f1"), *zero_fill,
        ]) if not is_zero_gt else None
        verified_severity_coverage = _complete_mean([
            *completed_metric_values("verified_severity_coverage"), *zero_fill,
        ]) if not is_zero_gt else None
        completion_rate = _complete_mean([
            *completed_metric_values("phase4_completion_rate"), *zero_fill,
        ]) if not is_zero_gt else None
        def optional_run_mean(name: str) -> float | None:
            completed = completed_metric_values(name)
            evaluable = [float(value) for value in completed if value is not None]
            if not evaluable:
                return None
            # None means that the scenario declares no applicable control for
            # that run. Unevaluable declared controls are emitted as 0.0 by the
            # evaluator and therefore remain fail-closed here.
            return _mean([*evaluable, *zero_fill])
        negative_control_specificity = optional_run_mean(
            "negative_control_specificity"
        ) if not is_zero_gt else None
        negative_control_clean_run_rate = optional_run_mean(
            "negative_control_clean_run"
        ) if not is_zero_gt else None
        specificity = (
            _complete_mean([
                *[
                    float(
                        _get(run, "specificity")
                        if _get(run, "specificity") is not None
                        else (1.0 if int(_get(run, "false_positives", 0)) == 0 else 0.0)
                    )
                    for run in runs
                ],
                *zero_fill,
            ])
            if is_zero_gt
            else None
        )

        scenario_rows.append({
            "scenario_id": scenario_id,
            "split": split,
            "run_count": len(runs),
            "planned_run_count": planned_run_count,
            "completed_run_count": len(runs),
            "missing_run_count": missing_run_count,
            "completion_rate": round(len(runs) / planned_run_count, 3),
            "missing": missing_run_count > 0,
            "is_zero_gt": is_zero_gt,
            "scenario_score_pct": _round_optional(_complete_mean(run_scores)),
            "f1_score": _round_optional(f1),
            "precision": _round_optional(precision),
            "recall": _round_optional(recall),
            "specificity": _round_optional(specificity),
            "detection_f1": _round_optional(detection_f1),
            "quality_adjusted_f1": _round_optional(quality_adjusted_f1),
            "verified_f1": _round_optional(verified_f1),
            "verified_severity_coverage": _round_optional(verified_severity_coverage),
            "negative_control_specificity": _round_optional(
                negative_control_specificity
            ),
            "negative_control_clean_run_rate": _round_optional(
                negative_control_clean_run_rate
            ),
            "negative_control_run_count": sum(
                _get(run, "negative_control_clean_run") is not None for run in runs
            ),
            "phase4_completion_rate": _round_optional(completion_rate),
            "quality_path_coverage": _round_optional(optional_run_mean("quality_path_coverage")),
            "verified_path_coverage": _round_optional(optional_run_mean("verified_path_coverage")),
            **{
                name: _round_optional(optional_run_mean(name))
                for name in (
                    "mhr_1", "mhr_2", "mhr_3",
                    "mhr_1_credited", "mhr_2_credited", "mhr_3_credited",
                    "mhr_1_verified", "mhr_2_verified", "mhr_3_verified",
                    "dhr_1", "dhr_2", "dhr_3",
                    "dhr_1_verified", "dhr_2_verified", "dhr_3_verified",
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

    planned_run_count = sum(int(s["planned_run_count"]) for s in scenario_rows)
    completed_run_count = sum(int(s["completed_run_count"]) for s in scenario_rows)
    missing_runs = {
        s["scenario_id"]: int(s["missing_run_count"])
        for s in scenario_rows if int(s["missing_run_count"]) > 0
    }
    return {
        "run_count": len(rows),
        "planned_run_count": planned_run_count,
        "completed_run_count": completed_run_count,
        "missing_run_count": planned_run_count - completed_run_count,
        "completion_rate": (
            round(completed_run_count / planned_run_count, 3)
            if planned_run_count else None
        ),
        **suite_summary,
        "missing_scenarios": missing,
        "missing_runs": missing_runs,
        "per_scenario": {s["scenario_id"]: s for s in scenario_rows},
        "per_split": per_split,
    }


__all__ = ["aggregate_evaluations"]
