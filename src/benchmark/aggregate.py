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
import math

from src.benchmark.evaluator import EvaluationResult
from src.benchmark.funnel import STAGES
from src.benchmark.comparability import configuration_identity, identity_key


EvaluationLike = EvaluationResult | Mapping[str, Any]

_MISSING = object()
_POSITIVE_ONLY_METRICS = frozenset({
    "f1_score", "detection_f1", "quality_adjusted_f1", "verified_f1",
    "phase4_completion_rate", "quality_path_coverage", "verified_path_coverage",
    "precision", "recall", "hallucination_rate",
    "critical_recall", "high_recall", "medium_recall", "low_recall",
    "phase3_device_completion_rate",
    "phase5_target_attempt_coverage", "phase5_target_coverage",
    "phase5_compromise_rate", "phase5_hop_coverage", "phase5_chain_faithfulness",
    "mhr_1", "mhr_2", "mhr_3", "mhr_1_credited", "mhr_2_credited", "mhr_3_credited",
    "mhr_1_verified", "mhr_2_verified", "mhr_3_verified",
})
_SEVERITY_METRICS = {
    "critical_recall": "critical", "high_recall": "high",
    "medium_recall": "medium", "low_recall": "low",
}
_MHR_METRICS = {"mhr_1": 1, "mhr_2": 2, "mhr_3": 3,
                "mhr_1_credited": 1, "mhr_2_credited": 2, "mhr_3_credited": 3,
                "mhr_1_verified": 1, "mhr_2_verified": 2, "mhr_3_verified": 3}
_PIVOT_METRICS = frozenset({
    "phase5_pivot_attempts", "phase5_pivot_successes", "phase5_pivot_success_rate",
})
_VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
def _metric_value(result: EvaluationLike, metric: str) -> Any:
    if metric == "scenario_score_pct":
        raw = _get(result, "scenario_score_pct", _MISSING)
        return None if raw is _MISSING else raw
    if metric == "specificity":
        value = _get(result, "specificity", _MISSING)
        if value is not _MISSING and value is not None:
            return value
        return None
    aliases = {"f1_score": "f1"}
    value = _get(result, metric, _MISSING)
    if value is _MISSING:
        value = _get(result, aliases.get(metric, metric), _MISSING)
    return value


def _finite_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float)) and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def _nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _normalise_severity(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalised = value.strip().casefold()
    return normalised if normalised in _VALID_SEVERITIES else None


def _depth_key(value: Any) -> int | None:
    if _nonnegative_int(value):
        return value
    # str.isdigit() accepts Unicode numerals that int() cannot parse. Restrict
    # serialized depth keys to decimal ASCII before converting them.
    if isinstance(value, str) and value and all("0" <= char <= "9" for char in value):
        return int(value)
    return None


def _compact_severity_population(result: EvaluationLike) -> dict[str, int] | None:
    """Return a validated, collision-free compact GT severity histogram."""
    totals = _get(result, "gt_by_severity", _MISSING)
    total_gt = _get(result, "total_gt_vulns", _MISSING)
    if not isinstance(totals, Mapping) or not _nonnegative_int(total_gt):
        return None
    normalised: dict[str, int] = {}
    for raw_severity, count in totals.items():
        severity = _normalise_severity(raw_severity)
        if severity is None or not _nonnegative_int(count) or severity in normalised:
            return None
        normalised[severity] = count
    return normalised if sum(normalised.values()) == total_gt else None


def _complete_gt_matches(result: EvaluationLike, required_field: str | None = None) -> bool:
    total = _get(result, "total_gt_vulns", _MISSING)
    matches = _get(result, "matches", _MISSING)
    return (
        _nonnegative_int(total)
        and isinstance(matches, list)
        and len(matches) == total
        and all(
            isinstance(match, Mapping)
            and (
                required_field is None
                or (
                    required_field == "gt_severity"
                    and _normalise_severity(match.get(required_field)) is not None
                )
                or (
                    required_field == "gt_hop_depth"
                    and _depth_key(match.get(required_field)) is not None
                )
                or (required_field not in {"gt_severity", "gt_hop_depth"} and required_field in match)
            )
            for match in matches
        )
    )


def _metric_state(result: EvaluationLike, metric: str, *, zero_gt: bool) -> str:
    """Classify one run value without treating an absent field as undefined."""
    value = _metric_value(result, metric)
    if metric == "specificity" and not zero_gt:
        return "not_applicable"
    if metric == "scenario_score_pct" and zero_gt:
        specificity = _metric_value(result, "specificity")
        if not _finite_number(specificity):
            return "unavailable"
    if metric in _POSITIVE_ONLY_METRICS and zero_gt:
        return "not_applicable" if value is None or _finite_number(value) else "unavailable"
    if _finite_number(value):
        return "evaluated"
    # Invalid supplied values are unavailable; they cannot be reinterpreted as
    # an empty denominator merely because a default counter happens to be zero.
    supplied = _get(result, metric, _MISSING)
    if metric == "f1_score":
        supplied = _get(result, "f1", supplied)
    if supplied is not _MISSING and supplied is not None:
        return "unavailable"
    if metric in _PIVOT_METRICS:
        return "unavailable"

    if metric in _SEVERITY_METRICS:
        severity = _SEVERITY_METRICS[metric]
        totals = _compact_severity_population(result)
        if totals is not None:
            population = totals.get(severity, 0)
        elif _complete_gt_matches(result, "gt_severity"):
            matches = _get(result, "matches")
            population = sum(
                _normalise_severity(match.get("gt_severity")) == severity
                for match in matches if isinstance(match, Mapping)
            )
        else:
            return "unavailable"
        if population == 0 and _get(result, "total_gt_vulns", None) == 0:
            return "not_applicable"
        return "undefined" if population == 0 else "unavailable"

    if metric in _MHR_METRICS:
        histogram = _get(result, "gt_at_depth", _MISSING)
        matches = _get(result, "matches", _MISSING)
        total_gt = _get(result, "total_gt_vulns", _MISSING)
        histogram_complete = (
            isinstance(histogram, Mapping)
            and _nonnegative_int(total_gt)
            and all(
                _depth_key(raw_depth) is not None and _nonnegative_int(count)
                for raw_depth, count in histogram.items()
            )
            and sum(histogram.values()) == total_gt
        )
        matches_complete = _complete_gt_matches(result, "gt_hop_depth")
        if not histogram_complete and not matches_complete:
            return "unavailable"
        depth = _MHR_METRICS[metric]
        population = None
        if histogram_complete:
            population = sum(
                count for raw_depth, count in histogram.items()
                if _depth_key(raw_depth) >= depth
            )
        else:
            population = sum(
                1 for match in matches
                if _depth_key(match.get("gt_hop_depth", _MISSING)) is not None
                and _depth_key(match["gt_hop_depth"]) >= depth
            )
        if population == 0 and _get(result, "total_gt_vulns", 0) > 0:
            return "undefined"
        return "not_applicable" if population == 0 else "unavailable"

    if metric == "phase4_completion_rate":
        funnel = _get(result, "funnel", _MISSING)
        stages = funnel.get("stages", {}) if isinstance(funnel, Mapping) else {}
        confirmed = stages.get("confirmed") if isinstance(stages, Mapping) else None
        if not isinstance(confirmed, Mapping) or confirmed.get("available") is not True:
            return "unavailable"
        filtered = stages.get("filtered") if isinstance(stages, Mapping) else None
        # The canonical funnel population wins over legacy secondary counters;
        # an explicit zero there is a measured empty denominator.
        candidates = filtered.get("predictions") if isinstance(filtered, Mapping) else _MISSING
        if not _nonnegative_int(candidates):
            candidates = _get(result, "phase4_candidates", _MISSING)
        if not _nonnegative_int(candidates):
            return "unavailable"
        return "undefined" if candidates == 0 else "unavailable"

    if metric in {"quality_path_coverage", "verified_path_coverage"}:
        total_paths = _get(result, "total_attack_paths", _MISSING)
        if not _nonnegative_int(total_paths):
            return "unavailable"
        if total_paths == 0 and _get(result, "intrusion_paths_available", _MISSING) is True:
            return "undefined"
        return "unavailable"

    if metric in {"phase5_target_attempt_coverage", "phase5_target_coverage", "phase5_compromise_rate",
                  "phase5_hop_coverage", "phase5_chain_faithfulness"}:
        if _get(result, "phase5_metrics_available", _MISSING) is not True:
            return "unavailable"
        denominator = (
            _get(result, "phase5_targets_total", _MISSING)
            if metric != "phase5_compromise_rate"
            else _get(result, "phase5_targets_attempted", _MISSING)
        )
        if metric in {"phase5_hop_coverage", "phase5_chain_faithfulness"}:
            denominator = (
                _get(result, "phase5_expected_hops", _MISSING)
                if metric == "phase5_hop_coverage"
                else _get(result, "phase5_observed_hops", _MISSING)
            )
        if not _nonnegative_int(denominator):
            return "unavailable"
        return "undefined" if denominator == 0 else "unavailable"

    if metric == "phase3_device_completion_rate":
        if _get(result, "phase3_metrics_available", _MISSING) is not True:
            return "unavailable"
        total = _get(result, "phase3_devices_total", _MISSING)
        if not _nonnegative_int(total):
            return "unavailable"
        return "undefined" if total == 0 else "unavailable"
    return "unavailable"


def _metric_coverage(
    runs: list[EvaluationLike], metric: str, *, expected: int, zero_gt: bool | None,
) -> dict[str, Any]:
    counts = {state: 0 for state in ("evaluated", "undefined", "unavailable", "not_applicable")}
    for run in runs:
        run_zero_gt = bool(_get(run, "is_zero_gt", False)) if zero_gt is None else zero_gt
        counts[_metric_state(run, metric, zero_gt=run_zero_gt)] += 1
    missing = max(0, expected - len(runs))
    if zero_gt is True and metric in _POSITIVE_ONLY_METRICS:
        counts["not_applicable"] += missing
    else:
        counts["unavailable"] += missing
    counts["expected"] = expected
    counts["unit"] = "attempts"
    return {"expected": counts.pop("expected"), "evaluated": counts["evaluated"],
            "undefined": counts["undefined"], "unavailable": counts["unavailable"],
            "not_applicable": counts["not_applicable"], "unit": counts.pop("unit")}


def _scenario_metric_value(
    runs: list[EvaluationLike], metric: str, *, expected: int, zero_gt: bool,
) -> float | None:
    coverage = _metric_coverage(runs, metric, expected=expected, zero_gt=zero_gt)
    if coverage["unavailable"]:
        return None
    values = [
        float(_metric_value(run, metric)) for run in runs
        if _metric_state(run, metric, zero_gt=zero_gt) == "evaluated"
    ]
    return _round_optional(_mean(values))


_MACRO_METRICS = {
    "macro_scenario_score_pct": "scenario_score_pct",
    "macro_positive_f1": "f1_score",
    "macro_detection_f1": "detection_f1",
    "macro_quality_adjusted_f1": "quality_adjusted_f1",
    "macro_verified_f1": "verified_f1",
    "macro_phase4_completion_rate": "phase4_completion_rate",
    "macro_quality_path_coverage": "quality_path_coverage",
    "macro_verified_path_coverage": "verified_path_coverage",
    "macro_phase5_target_attempt_coverage": "phase5_target_attempt_coverage",
    "macro_phase5_target_coverage": "phase5_target_coverage",
    "macro_phase5_compromise_rate": "phase5_compromise_rate",
    "macro_phase5_hop_coverage": "phase5_hop_coverage",
    "macro_phase5_pivot_success_rate": "phase5_pivot_success_rate",
    "macro_phase5_chain_faithfulness": "phase5_chain_faithfulness",
    "macro_mhr_1": "mhr_1", "macro_mhr_2": "mhr_2", "macro_mhr_3": "mhr_3",
    "macro_mhr_1_credited": "mhr_1_credited", "macro_mhr_2_credited": "mhr_2_credited",
    "macro_mhr_3_credited": "mhr_3_credited", "macro_mhr_1_verified": "mhr_1_verified",
    "macro_mhr_2_verified": "mhr_2_verified", "macro_mhr_3_verified": "mhr_3_verified",
    "macro_positive_precision": "precision", "macro_positive_recall": "recall",
    "macro_hallucination_rate": "hallucination_rate",
    "macro_critical_recall": "critical_recall", "macro_high_recall": "high_recall",
    "macro_medium_recall": "medium_recall", "macro_low_recall": "low_recall",
    "macro_phase3_device_completion_rate": "phase3_device_completion_rate",
    "macro_zero_gt_specificity": "specificity",
}
_METRIC_FIELDS = tuple(dict.fromkeys(_MACRO_METRICS.values()))


def _summary_attempts(scenarios: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "unit": "attempts",
        **{
            key: sum(int((scenario.get("attempts") or {}).get(key, 0)) for scenario in scenarios)
            for key in ("expected", "observed", "evaluated", "missing", "unavailable")
        },
    }


def _summary_metric_coverage(
    scenarios: list[dict[str, Any]], source: str,
) -> dict[str, Any]:
    counts = {state: 0 for state in ("evaluated", "undefined", "unavailable", "not_applicable")}
    for scenario in scenarios:
        coverage = (scenario.get("metric_coverage") or {}).get(source, {})
        if coverage.get("expected", 0) == 0:
            state = "not_applicable"
        elif coverage.get("unavailable", 0):
            state = "unavailable"
        elif _finite_number(scenario.get(source)):
            state = "evaluated"
        elif coverage.get("undefined", 0):
            state = "undefined"
        elif coverage.get("not_applicable", 0):
            state = "not_applicable"
        else:
            state = "unavailable"
        counts[state] += 1
    return {
        "unit": "scenarios", "expected": len(scenarios),
        "evaluated": counts["evaluated"], "undefined": counts["undefined"],
        "unavailable": counts["unavailable"], "not_applicable": counts["not_applicable"],
    }


def _summary_metric_value(
    scenarios: list[dict[str, Any]], macro: str, source: str,
) -> float | None:
    coverage = _summary_metric_coverage(scenarios, source)
    if coverage["unavailable"]:
        return None
    values = [
        float(scenario[source]) for scenario in scenarios
        if _finite_number(scenario.get(source))
        and _summary_metric_coverage([scenario], source)["evaluated"] == 1
    ]
    return _round_optional(_mean(values))


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


_SCENARIO_METADATA_FIELDS = {
    "scenario_id", "split", "run_count", "missing", "is_zero_gt",
    "comparability_identity", "comparability_status", "comparability_reason",
    "attempts", "metric_coverage",
}


def _mark_non_comparable(row: dict[str, Any], reason: str) -> dict[str, Any]:
    for key in tuple(row):
        if key not in _SCENARIO_METADATA_FIELDS:
            row[key] = None
    row["comparability_status"] = "not_comparable"
    row["comparability_reason"] = reason
    return row


def _unpublished_summary(scenarios: list[dict[str, Any]], reason: str) -> dict[str, Any]:
    """Keep counts/diagnostics while withholding every official macro metric."""
    # Build through the normal summary path so the unpublished shape and its
    # coverage diagnostics stay synchronized as macro fields evolve.
    summary = _summary_for_scenarios(scenarios)
    summary["funnel"] = None
    for key in summary:
        if key.startswith("macro_"):
            summary[key] = None
    summary["comparability_status"] = "not_comparable"
    summary["comparability_reason"] = reason
    return summary


def _validated_result_identity(result: EvaluationLike) -> tuple[dict[str, Any] | None, str | None]:
    raw = _get(result, "comparability_identity")
    identity, reason = configuration_identity(raw)
    if identity is None:
        return None, _get(result, "comparability_reason") or reason
    return identity, None


def _aggregate_funnel(values: list[dict]) -> dict:
    """Macro stage metrics; missing runs/stages stay visible and unavailable.

    Counts are means per run/scenario, not fictional integer totals. Precision
    is undefined for an empty report, so its available denominator is explicit.
    """
    result = {"schema_version": "funnel-v1", "aggregation": "macro", "stages": {}}
    def stage_map(value: Any) -> Mapping[str, Any]:
        raw = value.get("stages") if isinstance(value, Mapping) else None
        return raw if isinstance(raw, Mapping) else {}
    def stage_value(value: Any, name: str) -> Mapping[str, Any]:
        stage = stage_map(value).get(name, {})
        return stage if isinstance(stage, Mapping) else {}

    for name in STAGES:
        stages = [stage_value(v, name) for v in values]
        complete = bool(stages) and all(s.get("available") for s in stages)
        row = {"available": complete, "evaluated": sum(bool(s.get("available")) for s in stages), "expected": len(stages)}
        for key in ("predictions", "true_positives", "false_positives", "false_negatives", "invalid_evidence"):
            row[key] = _round_optional(_complete_mean(s.get(key) for s in stages)) if complete else None
        for key in ("precision", "recall", "f1"):
            defined = [s[key] for s in stages if s.get(key) is not None]
            row[key] = _round_optional(_mean(defined)) if complete else None
            row[f"{key}_defined"] = len(defined)
        result["stages"][name] = row
    return result


def _summary_for_scenarios(
    scenarios: list[dict[str, Any]], *, comparable: bool = True, reason: str | None = None,
) -> dict[str, Any]:
    if not comparable:
        return _unpublished_summary(scenarios, reason or "configuration identities are incompatible")
    summary = {
        "comparability_status": "comparable",
        "comparability_reason": None,
        "scenario_count": len(scenarios),
        "attempts": _summary_attempts(scenarios),
        "funnel": _aggregate_funnel([s.get("funnel", {}) for s in scenarios]),
        "metric_coverage": {},
    }
    for macro, source in _MACRO_METRICS.items():
        summary[macro] = _summary_metric_value(scenarios, macro, source)
        summary["metric_coverage"][macro] = _summary_metric_coverage(scenarios, source)
    return summary


def aggregate_evaluations(
    evaluations: Iterable[EvaluationLike],
    *,
    expected_scenarios: Iterable[str | int] | None = None,
    scenario_splits: Mapping[str | int, str] | None = None,
    expected_attempts: Mapping[str | int, int] | None = None,
    observed_attempts: Mapping[str | int, int] | None = None,
) -> dict[str, Any]:
    """Aggregate evaluations with equal weight per scenario.

    Multiple seeds/runs for one scenario are averaged before the suite macro is
    computed. Scenarios listed in ``expected_scenarios`` but missing from the
    results are retained for diagnostics and are not silently converted to a
    measured zero. Attempt counts are explicit when the caller knows the plan.
    ``scenario_splits`` is intentionally supplied by the caller/evaluator-side
    manifest rather than inferred from agent-controlled run output.
    """
    def validate_counts(values: Mapping[str | int, int] | None, label: str) -> dict[str, int]:
        if values is None:
            return {}
        if not isinstance(values, Mapping):
            raise TypeError(f"{label} must be a mapping")
        normalized: dict[str, int] = {}
        for raw_key, value in values.items():
            key = str(raw_key)
            if key in normalized:
                raise ValueError(f"{label} has duplicate scenario key {key!r}")
            if not _nonnegative_int(value):
                raise ValueError(f"{label}[{key!r}] must be a non-negative integer")
            normalized[key] = value
        return normalized

    expected_count_map = validate_counts(expected_attempts, "expected_attempts")
    observed_count_map = validate_counts(observed_attempts, "observed_attempts")
    rows = list(evaluations)
    split_map = {str(k): str(v) for k, v in (scenario_splits or {}).items()}
    grouped: dict[str, list[EvaluationLike]] = defaultdict(list)
    for row in rows:
        scenario_id = str(_get(row, "scenario_id", ""))
        if not scenario_id:
            raise ValueError("Evaluation result is missing scenario_id")
        grouped[scenario_id].append(row)

    expected = {str(s) for s in (expected_scenarios or [])}
    all_scenario_ids = set(grouped) | expected | set(expected_count_map) | set(observed_count_map)
    scenario_rows: list[dict[str, Any]] = []
    missing: list[str] = []

    for scenario_id in sorted(all_scenario_ids, key=_scenario_sort_key):
        runs = grouped.get(scenario_id, [])
        if scenario_id in observed_count_map and observed_count_map[scenario_id] < len(runs):
            raise ValueError(
                f"observed_attempts[{scenario_id!r}] is smaller than received attempts"
            )
        observed_count = max(len(runs), observed_count_map.get(scenario_id, 0))
        configured_expected = expected_count_map.get(
            scenario_id, 1 if scenario_id in expected else len(runs)
        )
        if scenario_id in expected_count_map and configured_expected < observed_count:
            raise ValueError(
                f"expected_attempts[{scenario_id!r}] is smaller than observed attempts"
            )
        expected_count = max(configured_expected, observed_count)
        if not runs:
            if expected_count:
                missing.append(scenario_id)
            empty_coverage = {
                source: _metric_coverage([], source, expected=expected_count, zero_gt=None)
                for source in _METRIC_FIELDS
            }
            scenario_rows.append({
                "scenario_id": scenario_id,
                "split": split_map.get(scenario_id, "unassigned"),
                "run_count": 0,
                "missing": bool(expected_count),
                "comparability_identity": None,
                "comparability_status": "missing" if expected_count else "not_applicable",
                "comparability_reason": (
                    "scenario has no evaluated run" if expected_count
                    else "scenario has zero planned attempts"
                ),
                "funnel": _aggregate_funnel([{} for _ in range(expected_count)]),
                "is_zero_gt": None,
                "attempts": {
                    "unit": "attempts", "expected": expected_count,
                    "observed": observed_count, "evaluated": 0,
                    "missing": max(0, expected_count - observed_count),
                    "unavailable": observed_count,
                },
                "metric_coverage": empty_coverage,
                "scenario_score_pct": None,
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

        validated = [_validated_result_identity(run) for run in runs]
        run_identities = [identity for identity, _ in validated]
        run_identity_keys = [identity_key(identity) for identity in run_identities]
        comparability_reason = next(
            (
                str(reason)
                for (identity, reason), key in zip(validated, run_identity_keys)
                if key is None and reason
            ),
            None,
        )
        if comparability_reason is None and any(key is None for key in run_identity_keys):
            comparability_reason = "scenario has missing configuration identity"
        if comparability_reason is None and len(set(run_identity_keys)) != 1:
            comparability_reason = "scenario mixes incompatible configuration identities"
        scenario_comparable = comparability_reason is None
        scenario_identity = run_identities[0] if scenario_comparable else None

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

        run_scores = [_metric_value(run, "scenario_score_pct") for run in runs]
        score_states = [
            _metric_state(run, "scenario_score_pct", zero_gt=is_zero_gt)
            for run in runs
        ]
        scores = [
            float(score) for score, state in zip(run_scores, score_states)
            if state == "evaluated"
        ]
        metric_coverage = {
            source: _metric_coverage(
                runs, source, expected=expected_count, zero_gt=is_zero_gt
            )
            for source in _METRIC_FIELDS
        }

        scenario_row = {
            "scenario_id": scenario_id,
            "split": split,
            "run_count": len(runs),
            "missing": False,
            "funnel": _aggregate_funnel(
                [_get(run, "funnel", {}) for run in runs]
                + [{} for _ in range(max(0, expected_count - len(runs)))]
            ),
            "is_zero_gt": is_zero_gt,
            "attempts": {
                "unit": "attempts", "expected": expected_count,
                "observed": observed_count, "evaluated": sum(
                    state == "evaluated" for state in score_states
                ),
                "missing": max(0, expected_count - observed_count),
                "unavailable": max(0, observed_count - sum(
                    state == "evaluated" for state in score_states
                )),
            },
            "metric_coverage": metric_coverage,
            **{source: _scenario_metric_value(
                runs, source, expected=expected_count, zero_gt=is_zero_gt
            ) for source in _METRIC_FIELDS},
            "run_score_stddev_pct": (
                round(pstdev(scores), 3)
                if len(scores) > 1 and len(scores) == expected_count
                else (0.0 if len(scores) == expected_count == 1 else None)
            ),
            "run_score_min_pct": (
                round(min(scores), 3) if len(scores) == expected_count else None
            ),
            "run_score_max_pct": (
                round(max(scores), 3) if len(scores) == expected_count else None
            ),
            "comparability_identity": scenario_identity,
            "comparability_status": "comparable" if scenario_comparable else "not_comparable",
            "comparability_reason": comparability_reason,
        }
        scenario_rows.append(
            scenario_row if scenario_comparable
            else _mark_non_comparable(
                scenario_row, comparability_reason or "configuration is not comparable"
            )
        )

    comparable_rows = [row for row in scenario_rows if row.get("comparability_status") == "comparable"]
    scenario_identities = [identity_key(row.get("comparability_identity")) for row in comparable_rows]
    suite_reason = next(
        (
            row.get("comparability_reason")
            for row in scenario_rows
            if row.get("comparability_status") == "not_comparable"
        ),
        None,
    )
    if suite_reason is None and scenario_identities and len(set(scenario_identities)) != 1:
        suite_reason = "suite mixes incompatible configuration identities"
    suite_summary = _summary_for_scenarios(
        scenario_rows, comparable=suite_reason is None, reason=suite_reason,
    )
    per_split: dict[str, dict[str, Any]] = {}
    for split in sorted({s["split"] for s in scenario_rows}):
        split_scenarios = [s for s in scenario_rows if s["split"] == split]
        split_comparable_rows = [
            row for row in split_scenarios if row.get("comparability_status") == "comparable"
        ]
        split_keys = [identity_key(row.get("comparability_identity")) for row in split_comparable_rows]
        split_reason = next(
            (
                row.get("comparability_reason")
                for row in split_scenarios
                if row.get("comparability_status") == "not_comparable"
            ),
            None,
        )
        # Missing/not-applicable scenarios do not constitute an unknown
        # identity. Only supplied comparable rows can make a split incompatible.
        if split_reason is None and split_keys and len(set(split_keys)) != 1:
            split_reason = "split mixes incompatible configuration identities"
        per_split[split] = _summary_for_scenarios(
            split_scenarios, comparable=split_reason is None, reason=split_reason,
        )

    # A development score and a test score answer different questions. Keep
    # suite counts, but publish scores only within each group for mixed suites.
    mixed_splits = len(per_split) > 1
    if mixed_splits:
        suite_summary = {
            key: None if key.startswith("macro_") or key == "funnel" else value
            for key, value in suite_summary.items()
        }

    return {
        "run_count": len(rows),
        "mixed_splits": mixed_splits,
        **suite_summary,
        "missing_scenarios": missing,
        "per_scenario": {s["scenario_id"]: s for s in scenario_rows},
        "per_split": per_split,
    }


__all__ = ["aggregate_evaluations"]
