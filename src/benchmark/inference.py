"""Paired family-level inference for policy campaigns.

Implements the protocol choice already documented for this project:
estimate 95% confidence intervals by paired resampling of *families*
(bootstrap over family means), preserving the internal structure of
each family, and correct for multiplicity with Holm across the tested
metrics. Pure stdlib; deterministic for a fixed seed.

A result is only emitted with at least two independent families; below
that, callers must keep reporting descriptive statistics only.
"""
from __future__ import annotations

import random
import statistics

DEFAULT_RESAMPLES = 10_000
DEFAULT_SEED = 20261012


def bootstrap_mean_ci(values: list[float], *, seed: int = DEFAULT_SEED,
                      resamples: int = DEFAULT_RESAMPLES) -> dict:
    """Percentile bootstrap CI and two-sided p for the mean of ``values``."""
    if len(values) < 2:
        return {"available": False, "reason": "Fewer than two independent families"}
    observed = statistics.fmean(values)
    rng = random.Random(seed)
    n = len(values)
    means = []
    for _ in range(resamples):
        means.append(statistics.fmean(values[rng.randrange(n)] for _ in range(n)))
    means.sort()
    lo = means[int(0.025 * resamples)]
    hi = means[min(resamples - 1, int(0.975 * resamples))]
    below = sum(1 for m in means if m <= 0.0)
    above = resamples - below
    p_value = 1.0 if observed == 0 else min(1.0, 2.0 * min(below, above) / resamples)
    return {
        "available": True, "families": n, "mean": observed,
        "ci95_low": lo, "ci95_high": hi, "p_value": p_value,
        "resamples": resamples, "seed": seed,
    }


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


def family_inference(families: dict[str, list[dict]], metrics: tuple[str, ...], *,
                     delta_threshold: float | None = None,
                     seed: int = DEFAULT_SEED) -> dict:
    """Per-metric inference over family-mean paired deltas (llm - rules).

    ``families`` maps family_id -> list of per-pair delta dicts. Within a
    family, repetitions are averaged first; inference then treats each
    family as one independent unit.
    """
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
        result = bootstrap_mean_ci(list(family_means.values()), seed=seed)
        per_metric[metric] = result
        if result.get("available"):
            raw_p[metric] = result["p_value"]
    adjusted = holm_adjust(raw_p)
    for metric, result in per_metric.items():
        result["family_means"] = family_means_by_metric[metric]
        if result.get("available"):
            result["p_value_holm"] = adjusted[metric]
            # No threshold is assumed: the design freezes delta_min later.
            if delta_threshold is not None:
                result["ci95_excludes_delta"] = result["ci95_low"] > delta_threshold
    any_available = any(r.get("available") for r in per_metric.values())
    return {
        "available": any_available,
        "method": "paired bootstrap over family means (percentile 95% CI), Holm across metrics",
        "delta_threshold": delta_threshold,
        "metrics": per_metric,
        "reason": None if any_available else "Fewer than two independent families with values",
    }
