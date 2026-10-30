"""One-sided paired inference: a model that loses must never look significant.

The unit is the family. Below three families the module refuses to emit any
number, because a two-sided p-value around zero reported certainty for every
outcome, including a model performing strictly worse.
"""
from __future__ import annotations

import pytest

from src.benchmark.inference import (
    MIN_FAMILIES,
    bootstrap_paired_ci,
    decide,
    family_inference,
    holm_adjust,
    paired_difference_inference,
    sign_test_greater,
)


# --- the refusal -----------------------------------------------------------

def test_two_families_produce_no_number_at_all():
    result = paired_difference_inference([0.2, 0.3])
    assert result["available"] is False
    assert result.get("p_value") is None
    assert result.get("ci95_low") is None
    assert str(MIN_FAMILIES) in result["reason"]


def test_one_family_and_empty_input_are_refused():
    assert paired_difference_inference([0.4])["available"] is False
    assert paired_difference_inference([])["available"] is False


# --- the sign test ---------------------------------------------------------

def test_sign_test_p_value_is_exact_for_three_families():
    assert sign_test_greater([0.1, 0.2, 0.3])["p_value"] == pytest.approx(0.125)


def test_sign_test_never_rejects_a_mixed_result():
    assert sign_test_greater([0.1, -0.2, 0.3])["p_value"] == pytest.approx(0.5)


def test_sign_test_is_maximal_when_the_model_loses():
    """The defect this module used to have: a losing model scored p = 0."""
    assert sign_test_greater([-0.1, -0.2, -0.3])["p_value"] == pytest.approx(1.0)


def test_sign_test_five_successes_out_of_five():
    assert sign_test_greater([0.1] * 5)["p_value"] == pytest.approx(0.03125)


def test_sign_test_four_successes_out_of_five_is_not_significant():
    assert sign_test_greater([0.1, 0.1, -0.1, 0.1, 0.1])["p_value"] == pytest.approx(0.1875)


# --- the threshold ---------------------------------------------------------

def test_a_difference_equal_to_the_threshold_is_not_an_advantage():
    result = sign_test_greater([0.05, 0.05, 0.05], threshold=0.05)
    assert result["above_threshold"] == 0
    assert result["p_value"] == pytest.approx(1.0)


def test_a_difference_above_the_threshold_counts():
    result = sign_test_greater([0.2, 0.3, 0.4], threshold=0.05)
    assert result["above_threshold"] == 3
    assert result["p_value"] == pytest.approx(0.125)


# --- the bootstrap branch --------------------------------------------------

def test_bootstrap_is_used_above_seven_families():
    values = [0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5, 0.55]
    result = paired_difference_inference(values, seed=3, resamples=2000)
    assert result["method"].startswith("paired bootstrap")
    assert result["ci95_low"] < result["ci95_high"]
    assert result["p_value"] < 0.05


def test_bootstrap_p_value_is_never_zero():
    """A bounded resampling must not report certainty."""
    values = [0.5, 0.6, 0.7, 0.8, 0.9] * 2
    result = bootstrap_paired_ci(values, seed=5, resamples=500)
    assert result["p_value"] > 0.0


def test_bootstrap_refuses_two_families():
    assert bootstrap_paired_ci([0.2, 0.3])["available"] is False


# --- determinism -----------------------------------------------------------

def test_bootstrap_is_deterministic_for_a_fixed_seed():
    values = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
    first = bootstrap_paired_ci(values, seed=7, resamples=500)
    second = bootstrap_paired_ci(values, seed=7, resamples=500)
    assert first == second


# --- Holm and the decision rule -------------------------------------------

def test_holm_adjust_is_monotone_and_bounded():
    adjusted = holm_adjust({"a": 0.01, "b": 0.04, "c": 0.5})
    assert adjusted["a"] == pytest.approx(0.03)
    assert adjusted["b"] == pytest.approx(0.08)
    assert adjusted["c"] == pytest.approx(0.5)
    assert all(0 <= p <= 1 for p in adjusted.values())


def test_an_unavailable_result_is_never_decided():
    result = decide(paired_difference_inference([0.2, 0.3]))
    assert result["decidable"] is False


def test_five_agreeing_families_can_be_decided():
    families = {
        "fam-a": [{"m": 0.3}], "fam-b": [{"m": 0.4}], "fam-c": [{"m": 0.5}],
        "fam-d": [{"m": 0.35}], "fam-e": [{"m": 0.45}],
    }
    result = family_inference(families, ("m",), delta_threshold=0.1)
    metric = result["metrics"]["m"]
    assert metric["available"] is True
    assert metric["p_value"] == pytest.approx(0.03125)
    assert metric["p_value_holm"] == pytest.approx(0.03125)
    assert decide(metric)["reject_null"] is True


def test_three_agreeing_families_are_never_decided():
    """2^-3 = 0.125: a p-value that cannot reach alpha is not a decision."""
    metric = family_inference({"a": [{"m": 0.3}], "b": [{"m": 0.4}],
                               "c": [{"m": 0.5}]}, ("m",))["metrics"]["m"]
    assert metric["available"] is True
    decision = decide(metric)
    assert decision["decidable"] is False
    assert "cannot reach alpha" in decision["reason"]


def test_four_agreeing_families_are_never_decided():
    metric = family_inference({"a": [{"m": 0.3}], "b": [{"m": 0.4}],
                               "c": [{"m": 0.5}], "d": [{"m": 0.35}]},
                              ("m",))["metrics"]["m"]
    assert decide(metric)["decidable"] is False


# --- family aggregation ----------------------------------------------------

def test_repetitions_are_averaged_before_inference():
    families = {
        "fam-a": [{"m": 0.10}, {"m": 0.30}],
        "fam-b": [{"m": 0.20}],
        "fam-c": [{"m": 0.25}],
        "fam-d": [{"m": None}],
    }
    result = family_inference(families, ("m",))
    metric = result["metrics"]["m"]
    assert metric["family_means"] == {"fam-a": pytest.approx(0.20),
                                      "fam-b": pytest.approx(0.20),
                                      "fam-c": pytest.approx(0.25)}
    assert metric["families"] == 3


def test_family_inference_refuses_below_three_families():
    result = family_inference({"a": [{"m": 0.5}], "b": [{"m": 0.4}]}, ("m",))
    assert result["available"] is False
    assert "Fewer than 3" in result["reason"]
