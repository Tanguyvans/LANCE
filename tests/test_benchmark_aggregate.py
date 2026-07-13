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
) -> dict:
    return {
        "scenario_id": scenario_id,
        "scenario_score_pct": score,
        "f1_score": f1,
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

    def test_zero_gt_specificity_contributes_as_scenario_score(self):
        results = [
            _evaluation("1", score=80.0, f1=0.8),
            _evaluation("1h", score=100.0, zero_gt=True, specificity=1.0),
        ]

        aggregate = aggregate_evaluations(results)

        assert aggregate["macro_scenario_score_pct"] == 90.0
        assert aggregate["macro_positive_f1"] == 0.8
        assert aggregate["macro_zero_gt_specificity"] == 1.0

    def test_control_runs_are_averaged_within_control_scenario(self):
        results = [
            _evaluation("1h", score=100.0, zero_gt=True, specificity=1.0),
            _evaluation("1h", score=0.0, zero_gt=True, specificity=0.0),
        ]

        aggregate = aggregate_evaluations(results)

        assert aggregate["scenario_count"] == 1
        assert aggregate["per_scenario"]["1h"]["specificity"] == 0.5
        assert aggregate["macro_zero_gt_specificity"] == 0.5
        assert aggregate["macro_scenario_score_pct"] == 50.0

    def test_missing_expected_scenario_scores_zero(self):
        results = [_evaluation("1", score=100.0, f1=1.0)]

        aggregate = aggregate_evaluations(results, expected_scenarios={"1", "2"})

        assert aggregate["macro_scenario_score_pct"] == 50.0
        assert aggregate["missing_scenarios"] == ["2"]
        assert aggregate["per_scenario"]["2"]["run_count"] == 0
        assert aggregate["per_scenario"]["2"]["scenario_score_pct"] == 0.0


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
        assert aggregate["per_split"]["test"]["macro_scenario_score_pct"] == 50.0
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
