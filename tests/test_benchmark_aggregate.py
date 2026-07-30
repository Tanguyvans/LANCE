"""Tests for scenario-macro benchmark aggregation."""
from __future__ import annotations

import pytest

from src.benchmark.aggregate import aggregate_evaluations


def _evaluation(
    scenario_id: str,
    *,
    score: float,
    f1: float = 0.0,
    zero_gt: bool = False,
    specificity: float | None = None,
    split: str | None = None,
    total_gt: int = 1,
    precision: float | None = None,
    recall: float | None = None,
) -> dict:
    return {
        "scenario_id": scenario_id,
        "scenario_score_pct": score,
        "f1_score": f1,
        "precision": f1 if precision is None else precision,
        "recall": f1 if recall is None else recall,
        "is_zero_gt": zero_gt,
        "specificity": specificity,
        "split": split,
        "total_gt_vulns": 0 if zero_gt else total_gt,
        "false_positives": 0 if specificity == 1.0 else 1,
    }


class TestScenarioMacroAggregation:
    def test_large_scenario_does_not_dominate_small_scenario(self):
        results = [
            _evaluation("1", score=100.0, f1=1.0, total_gt=1),
            _evaluation("2", score=0.0, f1=0.0, total_gt=100),
        ]

        aggregate = aggregate_evaluations(results)

        assert aggregate["macro_scenario_score_pct"] == 50.0
        assert aggregate["macro_positive_f1"] == 0.5
        assert aggregate["scenario_count"] == 2

    def test_repeated_runs_are_averaged_before_scenarios(self):
        results = [
            *[_evaluation("1", score=100.0, f1=1.0) for _ in range(10)],
            _evaluation("2", score=0.0, f1=0.0),
        ]

        aggregate = aggregate_evaluations(results)

        assert aggregate["run_count"] == 11
        assert aggregate["scenario_count"] == 2
        assert aggregate["per_scenario"]["1"]["run_count"] == 10
        assert aggregate["macro_scenario_score_pct"] == 50.0
        assert aggregate["macro_positive_f1"] == 0.5
        assert aggregate["macro_positive_precision"] == 0.5
        assert aggregate["macro_positive_recall"] == 0.5
        assert aggregate["per_scenario"]["1"]["run_score_stddev_pct"] == 0.0

    def test_quality_path_and_mhr_variants_are_macro_aggregated(self):
        first = _evaluation("1", score=100.0, f1=1.0)
        first.update({
            "quality_path_coverage": 1.0,
            "verified_path_coverage": 0.5,
            "mhr_1": 1.0,
            "mhr_1_credited": 0.75,
            "mhr_1_verified": 0.5,
            "dhr_2": 1.0,
            "dhr_2_verified": 0.5,
        })
        second = _evaluation("2", score=50.0, f1=0.5)
        second.update({
            "quality_path_coverage": 0.0,
            "verified_path_coverage": 0.0,
            "mhr_1": 0.5,
            "mhr_1_credited": 0.25,
            "mhr_1_verified": 0.0,
            "dhr_2": 0.5,
            "dhr_2_verified": 0.0,
        })

        aggregate = aggregate_evaluations([first, second])

        assert aggregate["macro_quality_path_coverage"] == 0.5
        assert aggregate["macro_verified_path_coverage"] == 0.25
        assert aggregate["macro_mhr_1"] == 0.75
        assert aggregate["macro_mhr_1_credited"] == 0.5
        assert aggregate["macro_mhr_1_verified"] == 0.25
        assert aggregate["macro_dhr_2"] == 0.75
        assert aggregate["macro_dhr_2_verified"] == 0.25

    def test_reports_run_dispersion_within_scenario(self):
        aggregate = aggregate_evaluations([
            _evaluation("1", score=100.0, f1=1.0),
            _evaluation("1", score=0.0, f1=0.0),
        ])

        scenario = aggregate["per_scenario"]["1"]
        assert scenario["run_score_stddev_pct"] == 50.0
        assert scenario["run_score_min_pct"] == 0.0
        assert scenario["run_score_max_pct"] == 100.0

    def test_non_comparable_run_neutralizes_official_macro(self):
        current = _evaluation("1", score=100.0, f1=1.0)
        legacy = _evaluation("2", score=0.0, f1=1.0)
        legacy["scenario_score_pct"] = None
        legacy["scoring_policy"] = "strict-v3"

        aggregate = aggregate_evaluations([current, legacy])

        assert aggregate["per_scenario"]["2"]["scenario_score_pct"] is None
        assert aggregate["macro_scenario_score_pct"] is None

    def test_zero_gt_specificity_is_separate_from_positive_score(self):
        results = [
            _evaluation("1", score=80.0, f1=0.8),
            _evaluation("1h", score=100.0, zero_gt=True, specificity=1.0),
        ]

        aggregate = aggregate_evaluations(results)

        assert aggregate["macro_scenario_score_pct"] == 80.0
        assert aggregate["macro_positive_f1"] == 0.8
        assert aggregate["macro_zero_gt_specificity"] == 1.0
        assert aggregate["macro_zero_gt_clean_run_rate"] == 1.0

    def test_mixed_scenario_control_clean_runs_are_reported_separately(self):
        clean = _evaluation("20", score=80.0, f1=0.8)
        clean.update({
            "negative_control_specificity": 1.0,
            "negative_control_clean_run": 1.0,
        })
        violated = _evaluation("20", score=60.0, f1=0.6)
        violated.update({
            "negative_control_specificity": 0.75,
            "negative_control_clean_run": 0.0,
        })

        aggregate = aggregate_evaluations([clean, violated])

        scenario = aggregate["per_scenario"]["20"]
        assert scenario["negative_control_specificity"] == 0.875
        assert scenario["negative_control_clean_run_rate"] == 0.5
        assert aggregate["macro_negative_control_specificity"] == 0.875
        assert aggregate["macro_negative_control_clean_run_rate"] == 0.5
        assert scenario["negative_control_run_count"] == 2
        assert aggregate["negative_control_run_count"] == 2

    def test_run_without_declared_controls_is_excluded_from_control_average(self):
        clean = _evaluation("20", score=80.0, f1=0.8)
        clean.update({
            "negative_control_specificity": 1.0,
            "negative_control_clean_run": 1.0,
        })
        no_controls = _evaluation("20", score=60.0, f1=0.6)

        aggregate = aggregate_evaluations([clean, no_controls])

        scenario = aggregate["per_scenario"]["20"]
        assert scenario["negative_control_specificity"] == 1.0
        assert scenario["negative_control_clean_run_rate"] == 1.0
        assert scenario["negative_control_run_count"] == 1

    def test_control_runs_are_averaged_within_control_scenario(self):
        results = [
            _evaluation("1h", score=100.0, zero_gt=True, specificity=1.0),
            _evaluation("1h", score=0.0, zero_gt=True, specificity=0.0),
        ]

        aggregate = aggregate_evaluations(results)

        assert aggregate["scenario_count"] == 1
        assert aggregate["per_scenario"]["1h"]["specificity"] == 0.5
        assert aggregate["macro_zero_gt_specificity"] == 0.5
        assert aggregate["macro_scenario_score_pct"] is None

    def test_missing_expected_scenario_scores_zero(self):
        results = [_evaluation("1", score=100.0, f1=1.0)]
        results[0].update({
            "detection_f1": 1.0,
            "verified_f1": 1.0,
            "verified_severity_coverage": 1.0,
            "quality_adjusted_f1": 1.0,
            "phase4_completion_rate": 1.0,
        })

        aggregate = aggregate_evaluations(results, expected_scenarios={"1", "2"})

        assert aggregate["macro_scenario_score_pct"] == 50.0
        assert aggregate["macro_detection_f1"] == 0.5
        assert aggregate["macro_verified_f1"] == 0.5
        assert aggregate["macro_verified_severity_coverage"] == 0.5
        assert aggregate["missing_scenarios"] == ["2"]
        assert aggregate["per_scenario"]["2"]["run_count"] == 0
        assert aggregate["per_scenario"]["2"]["scenario_score_pct"] == 0.0

    def test_missing_seed_repetitions_score_zero(self):
        completed = _evaluation("20", score=100.0, f1=1.0)
        completed.update({
            "detection_f1": 1.0,
            "quality_adjusted_f1": 1.0,
            "verified_f1": 1.0,
            "verified_severity_coverage": 1.0,
            "phase4_completion_rate": 1.0,
            "negative_control_specificity": 1.0,
            "negative_control_clean_run": 1.0,
        })

        aggregate = aggregate_evaluations(
            [completed],
            expected_scenarios={"20"},
            expected_repetitions={"20": 3},
        )

        scenario = aggregate["per_scenario"]["20"]
        assert scenario["scenario_score_pct"] == 33.333
        assert scenario["verified_f1"] == 0.333
        assert scenario["negative_control_clean_run_rate"] == 0.333
        assert scenario["missing_run_count"] == 2
        assert aggregate["planned_run_count"] == 3
        assert aggregate["completed_run_count"] == 1
        assert aggregate["completion_rate"] == 0.333
        assert aggregate["missing_runs"] == {"20": 2}


class TestSplitAggregation:
    def test_reports_independent_split_macros(self):
        results = [
            _evaluation("1", score=100.0, f1=1.0),
            _evaluation("2", score=0.0, f1=0.0),
            _evaluation("1h", score=100.0, zero_gt=True, specificity=1.0),
        ]
        splits = {"1": "train", "2": "test", "1h": "test"}

        aggregate = aggregate_evaluations(results, scenario_splits=splits)

        assert aggregate["per_split"]["train"]["macro_scenario_score_pct"] == 100.0
        assert aggregate["per_split"]["test"]["macro_scenario_score_pct"] == 0.0
        assert aggregate["per_split"]["test"]["macro_positive_f1"] == 0.0
        assert aggregate["per_split"]["test"]["macro_zero_gt_specificity"] == 1.0

    def test_conflicting_split_metadata_fails_closed(self):
        results = [_evaluation("1", score=100.0, f1=1.0, split="train")]

        with pytest.raises(ValueError, match="conflicting split metadata"):
            aggregate_evaluations(results, scenario_splits={"1": "test"})

    def test_unassigned_split_is_explicit(self):
        aggregate = aggregate_evaluations([_evaluation("1", score=100.0, f1=1.0)])

        assert aggregate["per_scenario"]["1"]["split"] == "unassigned"
        assert aggregate["per_split"]["unassigned"]["scenario_count"] == 1


def test_empty_aggregate_is_well_defined():
    aggregate = aggregate_evaluations([])

    assert aggregate["run_count"] == 0
    assert aggregate["scenario_count"] == 0
    assert aggregate["macro_scenario_score_pct"] is None
    assert aggregate["macro_positive_f1"] is None
    assert aggregate["macro_zero_gt_specificity"] is None
