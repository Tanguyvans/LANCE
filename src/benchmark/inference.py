"""Paired family-level inference for policy campaigns.

The unit of inference is the **family**: repetitions inside a family are
averaged first, and each family then counts once. This module answers one
question only, and must not be read as answering any other:

    does the paired difference (A1 - D1), averaged over families, exceed the
    pre-registered threshold delta?

Everything is therefore one-sided. A two-sided p-value around zero answers a
different question ("is the difference non-zero?") and would be wrong here: a
model that performs *worse* must never look significant.

Below three families no inference is emitted at all. With n = 2 the sign test
cannot return a p-value below 0.25, and a bootstrap over two points is a
reported interval that no reader should trust. The module returns an explicit
refusal rather than a number.
"""
from __future__ import annotations

import math
import random
import statistics

DEFAULT_RESAMPLES = 10_000
DEFAULT_SEED = 20261012

# Under this many independent families, no p-value and no interval are emitted.
MIN_FAMILIES = 3
# Below this many families the exact sign test cannot reach a p-value under
# 0.05 even when every family agrees (2^-4 = 0.0625). A number that can never
# conclude is still a number a reader can misread, so the decision rule needs
# this floor rather than MIN_FAMILIES.
MIN_DECIDABLE_FAMILIES = 5
# At or above this many families, the resampling distribution replaces the
# exact sign test. Below it the exact test is both valid and conservative.
EXACT_SIGN_MAX = 7


def _too_few(n: int) -> dict:
    return {
        "available": False,
        "families": n,
        "reason": f"Fewer than {MIN_FAMILIES} independent families: no inference is emitted",
    }


def sign_test_greater(values: list[float], *, threshold: float = 0.0) -> dict:
    """Exact one-sided sign test of "the median paired difference is > threshold".

    The test counts families whose difference exceeds ``threshold``. Ties (a
    difference exactly equal to the threshold) count against the alternative,
    which keeps the test conservative: a model that merely matches the
    threshold is not credited with an advantage.
    """
    n = len(values)
    if n < MIN_FAMILIES:
        return _too_few(n)
    successes = sum(1 for value in values if value > threshold)
    if successes <= n / 2:
        p_value = 1.0
    else:
        tail = sum(math.comb(n, i) for i in range(successes, n + 1))
        p_value = min(1.0, tail * (0.5 ** n))
    return {
        "available": True,
        "families": n,
        "method": "exact one-sided sign test",
        "above_threshold": successes,
        "threshold": threshold,
        "p_value": p_value,
    }


def bootstrap_paired_ci(values: list[float], *, threshold: float = 0.0,
                        seed: int = DEFAULT_SEED,
                        resamples: int = DEFAULT_RESAMPLES) -> dict:
    """Paired bootstrap of the mean family difference, centred on the threshold.

    ``p_value`` is the one-sided probability of observing a resampled mean at or
    below the threshold, smoothed by one pseudo-count so that a bound of zero is
    never reported as certainty.
    """
    n = len(values)
    if n < MIN_FAMILIES:
        return _too_few(n)
    observed = statistics.fmean(values)
    shifted = [value - threshold for value in values]
    rng = random.Random(seed)
    means = sorted(
        statistics.fmean(shifted[rng.randrange(n)] for _ in range(n))
        for _ in range(resamples)
    )
    # The test is one-sided, so the reported bound is the 5th percentile: the
    # value the true difference exceeds with 95% confidence.
    lo = means[int(0.05 * resamples)]
    hi = means[min(resamples - 1, int(0.95 * resamples))]
    at_or_below = sum(1 for mean in means if mean <= 0.0)
    # The pseudo-count bounds the p-value away from zero: a finite resampling
    # cannot establish certainty, so the floor is reported rather than hidden.
    p_value = min(1.0, (at_or_below + 1) / (resamples + 1))
    return {
        "available": True,
        "families": n,
        "method": "paired bootstrap, one-sided against the threshold",
        "mean": observed,
        "threshold": threshold,
        # Interval of the difference itself, not of the difference minus delta.
        "ci95_low": lo + threshold,
        "ci95_high": hi + threshold,
        "p_value": p_value,
        "resamples": resamples,
        "seed": seed,
    }


def paired_difference_inference(values: list[float], *, threshold: float = 0.0,
                                seed: int = DEFAULT_SEED,
                                resamples: int = DEFAULT_RESAMPLES) -> dict:
    """One-sided inference on paired family differences, dispatching by size.

    Below ``MIN_FAMILIES`` the result carries the observed ``mean`` as a
    *descriptive* figure and nothing else: no p-value, no interval, no decision.
    Callers may report that mean, but must not read it as evidence.
    """
    n = len(values)
    if n < MIN_FAMILIES:
        refusal = _too_few(n)
        if values:
            refusal["mean"] = statistics.fmean(values)
            refusal["descriptive_only"] = True
        return refusal
    if n <= EXACT_SIGN_MAX:
        result = sign_test_greater(values, threshold=threshold)
        result["mean"] = statistics.fmean(values)
        return result
    return bootstrap_paired_ci(values, threshold=threshold, seed=seed,
                               resamples=resamples)


def holm_adjust(p_values: dict[str, float]) -> dict[str, float]:
    """Holm step-down adjusted p-values, preserving input keys."""
    ordered = sorted(p_values.items(), key=lambda item: item[1])
    m = len(ordered)
    adjusted: dict[str, float] = {}
    running = 0.0
    for rank, (key, p) in enumerate(ordered):
        running = max(running, min(1.0, (m - rank) * p))
        adjusted[key] = running
    return adjusted


def decide(result: dict, alpha: float = 0.05) -> dict:
    """Apply the pre-registered decision rule to one metric result.

    The rule rejects the null when the Holm-adjusted one-sided p-value is at
    most ``alpha`` **and** the effect clears the threshold. The exact sign test
    does not produce an interval, so the second condition is only applied when
    one exists: an interval that contradicts the p-value blocks the decision,
    an absent interval does not invent one. A result that is unavailable is
    never a decision.
    """
    if not result.get("available"):
        return {"decidable": False, "reason": result.get("reason")}
    families = result.get("families", 0)
    if families < MIN_DECIDABLE_FAMILIES:
        return {
            "decidable": False,
            "reason": (f"{families} families cannot reach alpha={alpha}: the exact "
                       f"sign test needs {MIN_DECIDABLE_FAMILIES} to reject"),
            "minimum_decidable_families": MIN_DECIDABLE_FAMILIES,
        }
    # A single metric has nothing to correct: Holm leaves its p-value unchanged,
    # so the raw value is used when no adjustment was applied.
    p_value = result.get("p_value_holm", result.get("p_value"))
    if p_value is None:
        return {"decidable": False, "reason": "No p-value available"}
    threshold = result.get("threshold", 0.0)
    mean = result.get("mean")
    lower = result.get("ci95_low")
    p_ok = p_value <= alpha
    # The effect must clear the threshold: use the interval when the method
    # provides one, the observed mean otherwise.
    if lower is not None:
        effect_ok = lower > threshold
        basis = "ci95_low"
    elif mean is not None:
        effect_ok = mean > threshold
        basis = "mean"
    else:
        return {"decidable": False, "reason": "No effect estimate available"}
    return {
        "decidable": True,
        "reject_null": bool(p_ok and effect_ok),
        "p_value_holm": p_value,
        "alpha": alpha,
        "effect_basis": basis,
        "effect_above_threshold": bool(effect_ok),
    }


def family_inference(families: dict[str, list[dict]], metrics: tuple[str, ...], *,
                     delta_threshold: float | None = None,
                     seed: int = DEFAULT_SEED) -> dict:
    """Per-metric one-sided inference over family-mean paired differences.

    ``families`` maps family_id -> list of per-pair difference dicts (A1 - D1).
    Repetitions inside a family are averaged before inference, so each family
    contributes exactly one observation. The threshold defaults to zero and is
    recorded with the result: it is the value the decision is taken against.
    """
    threshold = 0.0 if delta_threshold is None else delta_threshold
    per_metric: dict[str, dict] = {}
    raw_p: dict[str, float] = {}
    family_means_by_metric: dict[str, dict[str, float]] = {}
    for metric in metrics:
        family_means = {}
        for family, deltas in sorted(families.items()):
            known = [d[metric] for d in deltas if d.get(metric) is not None]
            if known:
                family_means[family] = statistics.fmean(known)
        family_means_by_metric[metric] = family_means
        result = paired_difference_inference(list(family_means.values()),
                                             threshold=threshold, seed=seed)
        per_metric[metric] = result
        if result.get("available"):
            raw_p[metric] = result["p_value"]
    adjusted = holm_adjust(raw_p)
    for metric, result in per_metric.items():
        result["family_means"] = family_means_by_metric[metric]
        if result.get("available"):
            result["p_value_holm"] = adjusted[metric]
    available_metrics = [name for name, r in per_metric.items() if r.get("available")]
    return {
        # A single available metric must not be read as "every metric is
        # inferable": both the count and the names are published.
        "available": bool(available_metrics),
        "available_metrics": sorted(available_metrics),
        "unavailable_metrics": sorted(set(per_metric) - set(available_metrics)),
        "method": ("one-sided paired inference over family means "
                   f"(exact sign test up to {EXACT_SIGN_MAX} families, "
                   "bootstrap beyond), Holm across metrics"),
        "delta_threshold": threshold if delta_threshold is not None else None,
        "minimum_families": MIN_FAMILIES,
        "metrics": per_metric,
        "reason": None if available_metrics else
                  f"Fewer than {MIN_FAMILIES} independent families with values",
    }
