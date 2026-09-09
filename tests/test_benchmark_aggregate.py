"""Tests for scenario-macro benchmark aggregation."""
from __future__ import annotations

import pytest

from src.benchmark.aggregate import aggregate_evaluations
from src.benchmark.evaluator import EvaluationResult
from src.benchmark.metric_contract import EVIDENCE_CONTRACT_VERSION, METRIC_CONTRACT_VERSION


_COMPARABILITY_IDENTITY = {
    "provider": "fixture-provider", "model": "fixture-model",
    "execution_profile": "full", "execution_profile_policy": "full",
    "blind": False, "max_cost_usd": None, "max_tool_calls": None,
    "effective_phases": [1, 2, 3, 4, 5, 6], "phase_models": {},
    "execution_profile_config": {"schema_version": "2", "name": "full"},
    "prompt_manifest_sha256": "fixture-prompts", "tool_manifest_sha256": "fixture-tools",
    "scoring_policy": "strict-v3", "metric_contract_version": METRIC_CONTRACT_VERSION,
    "evidence_contract_version": EVIDENCE_CONTRACT_VERSION,
}


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
        "comparability_identity": dict(_COMPARABILITY_IDENTITY),
    }


def _real_evaluation(scenario_id: str, identity: dict | None) -> EvaluationResult:
    return EvaluationResult(
        scenario_id=scenario_id,
        run_dir=f"/tmp/{scenario_id}",
        ground_truth_file=f"/tmp/{scenario_id}.yaml",
        scenario_score_pct=100.0,
        f1_score=1.0,
        precision=1.0,
        recall=1.0,
        total_gt_vulns=1,
        comparability_identity=identity,
    )


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
            "phase5_target_coverage": 0.75,
            "phase5_hop_coverage": 0.5,
            "phase5_pivot_success_rate": 1.0,
            "phase5_chain_faithfulness": 1.0,
        })
        second = _evaluation("2", score=50.0, f1=0.5)
        second.update({
            "quality_path_coverage": 0.0,
            "verified_path_coverage": 0.0,
            "mhr_1": 0.5,
            "mhr_1_credited": 0.25,
            "mhr_1_verified": 0.0,
            "phase5_target_coverage": 0.25,
            "phase5_hop_coverage": 0.0,
            "phase5_pivot_success_rate": 0.0,
            "phase5_chain_faithfulness": 0.5,
        })

        aggregate = aggregate_evaluations([first, second])

        assert aggregate["macro_quality_path_coverage"] == 0.5
        assert aggregate["macro_verified_path_coverage"] == 0.25
        assert aggregate["macro_mhr_1"] == 0.75
        assert aggregate["macro_mhr_1_credited"] == 0.5
        assert aggregate["macro_mhr_1_verified"] == 0.25

        assert aggregate["macro_phase5_target_coverage"] == 0.5
        assert aggregate["macro_phase5_hop_coverage"] == 0.25
        assert aggregate["macro_phase5_pivot_success_rate"] == 0.5
        assert aggregate["macro_phase5_chain_faithfulness"] == 0.75

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

    def test_invalid_control_is_not_recreated_or_dropped_from_the_average(self):
        valid = _evaluation("1h", score=100.0, zero_gt=True, specificity=1.0)
        invalid = {**valid, "scoring_policy": "strict-v3", "specificity": None,
                   "scenario_score_pct": None}
        for scenario_id in ("1h", "4h"):
            aggregate = aggregate_evaluations([valid, {**invalid, "scenario_id": scenario_id}])
            assert aggregate["per_scenario"][scenario_id]["specificity"] is None
            assert aggregate["macro_zero_gt_specificity"] is None
            assert aggregate["macro_scenario_score_pct"] is None

    def test_missing_expected_scenario_is_unavailable_not_zero(self):
        results = [_evaluation("1", score=100.0, f1=1.0)]

        aggregate = aggregate_evaluations(results, expected_scenarios={"1", "2"})

        assert aggregate["macro_scenario_score_pct"] is None
        assert aggregate["missing_scenarios"] == ["2"]
        assert aggregate["per_scenario"]["2"]["run_count"] == 0
        assert aggregate["per_scenario"]["2"]["scenario_score_pct"] is None
        assert aggregate["per_scenario"]["2"]["attempts"] == {
            "unit": "attempts", "expected": 1, "observed": 0,
            "evaluated": 0, "missing": 1, "unavailable": 0,
        }

    def test_non_comparable_summary_keeps_normal_summary_schema(self):
        comparable = aggregate_evaluations([_evaluation("1", score=100.0, f1=1.0)])
        different = _evaluation("2", score=0.0, f1=0.0)
        different["comparability_identity"]["model"] = "different-model"
        not_comparable = aggregate_evaluations([
            _evaluation("1", score=100.0, f1=1.0), different,
        ])

        assert set(not_comparable) == set(comparable)
        assert not_comparable["macro_scenario_score_pct"] is None


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

    def test_missing_expected_scenario_alone_does_not_make_split_incompatible(self):
        aggregate = aggregate_evaluations(
            [], expected_scenarios={"2"}, scenario_splits={"2": "test"}
        )

        split = aggregate["per_split"]["test"]
        assert split["comparability_status"] == "comparable"
        assert split["macro_scenario_score_pct"] is None

    def test_missing_expected_scenario_keeps_its_split_comparable(self):
        aggregate = aggregate_evaluations(
            [_evaluation("1", score=100.0, f1=1.0)],
            expected_scenarios={"1", "2"},
            scenario_splits={"1": "test", "2": "test"},
        )

        split = aggregate["per_split"]["test"]
        assert split["comparability_status"] == "comparable"
        assert split["macro_scenario_score_pct"] is None


def test_empty_aggregate_is_well_defined():
    aggregate = aggregate_evaluations([])

    assert aggregate["run_count"] == 0
    assert aggregate["scenario_count"] == 0
    assert aggregate["macro_scenario_score_pct"] is None
    assert aggregate["macro_positive_f1"] is None
    assert aggregate["macro_zero_gt_specificity"] is None


def test_r13_attempt_and_metric_coverage_do_not_invent_missing_scores():
    complete = _evaluation("1", score=100.0, f1=1.0)
    aggregate = aggregate_evaluations(
        [complete], expected_attempts={"1": 3}, observed_attempts={"1": 2}
    )
    scenario = aggregate["per_scenario"]["1"]
    assert aggregate["macro_scenario_score_pct"] is None
    assert scenario["attempts"] == {
        "unit": "attempts", "expected": 3, "observed": 2,
        "evaluated": 1, "missing": 1, "unavailable": 1,
    }
    coverage = scenario["metric_coverage"]["scenario_score_pct"]
    assert coverage["expected"] == 3
    assert coverage["evaluated"] == 1
    assert coverage["unavailable"] == 2


@pytest.mark.parametrize("value", [True, float("nan"), float("inf")])
def test_r13_invalid_primary_values_are_unavailable(value):
    row = _evaluation("1", score=value, f1=1.0)
    aggregate = aggregate_evaluations([row])
    assert aggregate["per_scenario"]["1"]["attempts"]["evaluated"] == 0
    assert aggregate["metric_coverage"]["macro_scenario_score_pct"]["unavailable"] == 1


def test_r13_zero_expected_is_explicitly_not_applicable():
    aggregate = aggregate_evaluations(
        [_evaluation("1", score=100.0, f1=1.0)], expected_attempts={"1": 1, "unused": 0}
    )
    assert aggregate["macro_scenario_score_pct"] == 100.0
    assert aggregate["per_scenario"]["unused"]["missing"] is False
    assert aggregate["per_scenario"]["unused"]["attempts"]["expected"] == 0


@pytest.mark.parametrize(("field", "metric", "value"), [
    ("gt_severity", "critical_recall", None),
    ("gt_severity", "critical_recall", ""),
    ("gt_hop_depth", "mhr_1", None),
    ("gt_hop_depth", "mhr_1", -1),
    ("gt_hop_depth", "mhr_1", "unknown"),
])
def test_invalid_gt_population_fields_are_unavailable(field, metric, value):
    row = _evaluation("1", score=100.0, f1=1.0)
    row.update({"matches": [{field: value}], "gt_at_depth": {}, "gt_by_severity": {},
               "recall_by_severity": {}})
    aggregate = aggregate_evaluations([row])
    assert aggregate["per_scenario"]["1"]["metric_coverage"][metric]["unavailable"] == 1


def test_unicode_depth_key_cannot_crash_or_prove_topology():
    row = _evaluation("1", score=100.0, f1=1.0)
    row.update({"matches": [], "gt_at_depth": {"²": 1}})
    aggregate = aggregate_evaluations([row])
    assert aggregate["per_scenario"]["1"]["metric_coverage"]["mhr_1"]["unavailable"] == 1


@pytest.mark.parametrize("bad_key", [None, False, "", "unknown"])
def test_invalid_compact_severity_keys_are_unavailable(bad_key):
    row = _evaluation("1", score=100.0, f1=1.0)
    row.update({"gt_by_severity": {bad_key: 1}, "critical_recall": None})
    aggregate = aggregate_evaluations([row])
    assert aggregate["per_scenario"]["1"]["metric_coverage"]["critical_recall"]["unavailable"] == 1


def test_compact_severity_accepts_case_and_rejects_normalisation_collisions():
    valid = _evaluation("1", score=100.0, f1=1.0)
    valid.update({"gt_by_severity": {"HIGH": 1}, "high_recall": 1.0})
    measured = aggregate_evaluations([valid])
    assert measured["per_scenario"]["1"]["metric_coverage"]["high_recall"]["evaluated"] == 1

    population_only = {
        **valid, "high_recall": None, "critical_recall": None,
    }
    classified = aggregate_evaluations([population_only])
    coverage = classified["per_scenario"]["1"]["metric_coverage"]
    assert coverage["high_recall"]["unavailable"] == 1
    assert coverage["critical_recall"]["undefined"] == 1

    collision = {**valid, "gt_by_severity": {"HIGH": 1, "high": 0}, "high_recall": None}
    rejected = aggregate_evaluations([collision])
    assert rejected["per_scenario"]["1"]["metric_coverage"]["high_recall"]["unavailable"] == 1


def test_primary_score_diagnostics_require_zero_gt_specificity():
    aggregate = aggregate_evaluations([
        _evaluation("1h", score=100.0, f1=1.0, zero_gt=True, specificity=None)
    ])
    row = aggregate["per_scenario"]["1h"]
    assert row["attempts"]["evaluated"] == 0
    assert row["scenario_score_pct"] is None
    assert row["run_score_stddev_pct"] is None
    assert row["run_score_min_pct"] is None
    assert row["run_score_max_pct"] is None


def test_real_evaluation_objects_compare_only_with_complete_same_configuration():
    first = _real_evaluation("1", _COMPARABILITY_IDENTITY)
    second = _real_evaluation("2", _COMPARABILITY_IDENTITY)
    aggregate = aggregate_evaluations([first, second])
    assert aggregate["macro_scenario_score_pct"] == 100.0
    assert aggregate["comparability_status"] == "comparable"

    incompatible_identity = {**_COMPARABILITY_IDENTITY, "model": "other-model"}
    incompatible = aggregate_evaluations([
        first, _real_evaluation("2", incompatible_identity),
    ])
    assert incompatible["macro_scenario_score_pct"] is None
    assert incompatible["comparability_status"] == "not_comparable"
    assert incompatible["per_scenario"]["2"]["comparability_status"] == "comparable"

    incomplete = aggregate_evaluations([_real_evaluation("1", None)])
    assert incomplete["macro_scenario_score_pct"] is None
    assert incomplete["per_scenario"]["1"]["comparability_status"] == "not_comparable"


@pytest.mark.parametrize("field,value", [
    ("provider", ""),
    ("effective_phases", [1, "2"]),
    ("phase_models", {"4": None}),
    ("phase_models", {4: "model-a", "4": "model-b"}),
    ("execution_profile_config", {}),
    ("max_cost_usd", float("nan")),
])
def test_invalid_configuration_identity_is_not_aggregated(field, value):
    identity = {**_COMPARABILITY_IDENTITY, field: value}
    aggregate = aggregate_evaluations([_real_evaluation("1", identity)])
    assert aggregate["macro_scenario_score_pct"] is None
    assert aggregate["comparability_status"] == "not_comparable"
