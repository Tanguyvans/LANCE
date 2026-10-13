from __future__ import annotations

import pytest

from src.benchmark.inference import bootstrap_mean_ci, family_inference, holm_adjust


def test_bootstrap_requires_two_families():
    assert bootstrap_mean_ci([0.4])["available"] is False
    assert bootstrap_mean_ci([])["available"] is False


def test_bootstrap_positive_effect_excludes_zero():
    result = bootstrap_mean_ci([0.2, 0.3, 0.25, 0.4, 0.35], seed=7, resamples=2000)
    assert result["available"] is True
    assert result["mean"] == pytest.approx(0.3)
    assert result["ci95_low"] > 0
    assert result["p_value"] < 0.05


def test_bootstrap_deterministic_for_fixed_seed():
    values = [0.1, -0.2, 0.3, 0.05]
    assert bootstrap_mean_ci(values, seed=3, resamples=500) == \
        bootstrap_mean_ci(values, seed=3, resamples=500)


def test_holm_adjust_is_monotone_and_bounded():
    adjusted = holm_adjust({"a": 0.01, "b": 0.04, "c": 0.5})
    assert adjusted["a"] == pytest.approx(0.03)
    assert adjusted["b"] == pytest.approx(0.08)
    assert adjusted["c"] == pytest.approx(0.5)
    assert all(0 <= p <= 1 for p in adjusted.values())


def test_family_inference_averages_repetitions_first():
    families = {
        "fam-a": [{"confirmed.recall": 0.10}, {"confirmed.recall": 0.30}],
        "fam-b": [{"confirmed.recall": 0.20}],
        "fam-c": [{"confirmed.recall": None}],
    }
    result = family_inference(families, ("confirmed.recall",), delta_threshold=0.05)
    assert result["available"] is True
    metric = result["metrics"]["confirmed.recall"]
    assert metric["family_means"] == {"fam-a": pytest.approx(0.20), "fam-b": 0.20}
    assert metric["families"] == 2


def test_family_inference_unavailable_below_two_families():
    result = family_inference({"only": [{"confirmed.recall": 0.5}]},
                              ("confirmed.recall",))
    assert result["available"] is False
    assert "Fewer than two" in result["reason"]
