"""V2 campaign identity, admission gate and family-level summary.

The V2 pilot harnesses emit calibration verdicts (``success``,
``evidence_only_not_admitted``), not strict-v3 TP/FP/FN. Two contracts must
therefore stay separate:

* ``pair_admission`` / ``campaign_admission`` compute ``mt_admissible`` from
  observable conditions and name every unmet one, instead of hardcoding
  ``False``.
* ``summarize_experiments`` maps the calibration verdicts onto paired
  per-family deltas and hands them to ``src.benchmark.inference``.

Nothing here deploys, executes, uploads or edits an existing record.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import json
from pathlib import Path
import statistics

from src.agent.audit_experiment import digest
from src.benchmark.inference import DEFAULT_SEED, family_inference

SCHEMA_VERSION = "v2-campaign-v1"
PROVIDER = "ollama-umons"
# The UMONS catalogue exposes one dense model and one mixture-of-experts model.
# Both are audited under the same prompts, tools and budgets.
MODEL_PANEL = ("qwen3.8:27b", "gemma4:26b-a4b-it-q4_K_M")
DEFAULT_MODEL = MODEL_PANEL[0]
V2_METRICS = ("task_success", "tool_calls", "wall_clock_s", "estimated_cost_usd")
PAIR_CONDITIONS = ("paired_execution_complete", "run_meta_present", "budget_parity",
                   "preflight_attested", "evidence_integrity", "usage_complete",
                   "evaluation_available")
CAMPAIGN_CONDITIONS = ("pair_conditions", "strict_v3_metrics_adopted",
                       "configuration_uniformity", "independent_families",
                       "minimum_repetitions")


def require_model(provider, model, *, pilot):
    """Refuse anything outside the declared panel before any lab or host access."""
    if provider != PROVIDER:
        raise ValueError(f"This {pilot} pilot requires provider {PROVIDER}; no provider fallback")
    if model not in MODEL_PANEL:
        raise ValueError(
            f"This {pilot} pilot requires a model from {', '.join(MODEL_PANEL)}; "
            "no provider fallback")
    return model


def default_campaign_id(kind, commit):
    """Stable campaign identifier: same frozen code, same campaign."""
    return f"{kind}-{str(commit)[:12]}"


def trial_identity(campaign_id, scenario_id, flaws, repetition):
    """``experiment`` block written into every ``run_meta.json``."""
    posture = "f1" if flaws else "f0"
    trial = f"{scenario_id}-{posture}-r{int(repetition)}"
    return {"id": campaign_id, "trial_id": trial, "family_id": scenario_id, "instance_id": trial}


def _condition(conditions, name, met, reason):
    conditions[name] = {"met": bool(met), "reason": None if met else reason}


def pair_admission(arms):
    """Evaluate the per-pair conditions from one trial's own artifacts.

    ``arms`` maps ``rules``/``llm`` to a dict with any of ``run_meta``,
    ``evaluation``, ``preflight`` and ``usage_complete``.
    """
    conditions = {}
    present = set(arms) == {"rules", "llm"}
    _condition(conditions, "paired_execution_complete", present,
               "Both decision arms must be present")
    metas = {policy: (arms.get(policy) or {}).get("run_meta") or {} for policy in ("rules", "llm")}
    _condition(conditions, "run_meta_present",
               present and all(metas[policy] for policy in ("rules", "llm")),
               "run_meta.json is required for each arm")
    budgets = [metas[policy].get("budgets") for policy in ("rules", "llm")]
    _condition(conditions, "budget_parity",
               present and budgets[0] is not None and budgets[0] == budgets[1],
               "Both arms must declare identical budgets")
    attestations = [((arms.get(policy) or {}).get("preflight") or {}).get("status")
                    for policy in ("rules", "llm")]
    _condition(conditions, "preflight_attested",
               present and all(status == "valid" for status in attestations),
               "Each arm needs a valid preflight attestation")
    _condition(conditions, "evidence_integrity",
               present and all(metas[policy].get("evidence_integrity_failed") is False
                               for policy in ("rules", "llm")),
               "Evidence archiving must not have failed")
    _condition(conditions, "usage_complete",
               (arms.get("llm") or {}).get("usage_complete") is True,
               "The LLM arm needs complete provider usage accounting")
    evaluations = {policy: (arms.get(policy) or {}).get("evaluation") or {}
                   for policy in ("rules", "llm")}
    _condition(conditions, "evaluation_available",
               present and all(evaluations[policy].get("success") is not None
                               for policy in ("rules", "llm")),
               "Both arms need a definite evaluation verdict")
    unmet = [name for name in PAIR_CONDITIONS if not conditions[name]["met"]]
    return {"met": not unmet, "conditions": conditions, "unmet": unmet}


def campaign_admission(pairs, *, families, repetitions, configurations=(),
                       strict_v3_metrics_adopted=False, minimum_families=2,
                       minimum_repetitions=3):
    """Combine per-pair conditions with the campaign-level requirements.

    ``repetitions`` maps family_id -> observed repetition count.
    """
    conditions = {}
    _condition(conditions, "pair_conditions",
               bool(pairs) and all(pair.get("met") is True for pair in pairs),
               "Every included pair must meet its own conditions")
    _condition(conditions, "strict_v3_metrics_adopted", strict_v3_metrics_adopted,
               "Calibration verdicts are not strict-v3 TP/FP/FN; an amendment is required")
    _condition(conditions, "configuration_uniformity",
               bool(configurations) and all(item == configurations[0] for item in configurations),
               "Every included arm must share provider, model, resources and budgets")
    _condition(conditions, "independent_families", int(families) >= minimum_families,
               f"At least {minimum_families} independent families are required; got {families}")
    fewest = min(repetitions.values()) if repetitions else 0
    _condition(conditions, "minimum_repetitions", fewest >= minimum_repetitions,
               f"Each family needs at least {minimum_repetitions} repetitions; lowest is {fewest}")
    unmet = [name for name in CAMPAIGN_CONDITIONS if not conditions[name]["met"]]
    return {"mt_admissible": not unmet, "conditions": conditions, "unmet": unmet}


def _object(path):
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def _number(value):
    if isinstance(value, bool):
        return int(value)
    return float(value) if type(value) in (int, float) else None


def _delta(left, right):
    return None if left is None or right is None else left - right


def read_trial(trial_dir):
    """Read one V2 trial directory; never invent missing measurements."""
    trial_dir = Path(trial_dir)
    comparisons = sorted(trial_dir.glob("comparison-*.json"))
    planned = _object(trial_dir / "planned.json")
    if len(comparisons) != 1:
        return {"trial_dir": str(trial_dir), "complete": False,
                "problem": "expected exactly one comparison file"}
    comparison = _object(comparisons[0])
    experiment = {}
    arms, evidence, evaluations = {}, {}, {}
    for policy in ("rules", "llm"):
        pointer = trial_dir / f"{policy}_dir.txt"
        run_dir = Path(pointer.read_text().strip()) if pointer.is_file() else None
        run_meta = _object(run_dir / "run_meta.json") if run_dir else {}
        attestation = _object(trial_dir / "preflight" / policy / "attestation.json")
        arm = (comparison.get("arms") or {}).get(policy) or {}
        experiment = experiment or run_meta.get("experiment") or {}
        arms[policy] = {"metrics": arm.get("metrics") or {}, "evaluation": arm.get("evaluation") or {}}
        evaluations[policy] = arm.get("evaluation") or {}
        evidence[policy] = {"run_meta": run_meta, "evaluation": arm.get("evaluation"),
                            "preflight": attestation,
                            "usage_complete": (arm.get("metrics") or {}).get("usage_complete")}
    deltas = {
        "task_success": _delta(_number(evaluations["llm"].get("success")),
                               _number(evaluations["rules"].get("success"))),
        "tool_calls": _delta(_number(arms["llm"]["metrics"].get("tool_calls")),
                             _number(arms["rules"]["metrics"].get("tool_calls"))),
        "wall_clock_s": _delta(_number(arms["llm"]["metrics"].get("wall_clock_s")),
                               _number(arms["rules"]["metrics"].get("wall_clock_s"))),
        "estimated_cost_usd": _number(arms["llm"]["metrics"].get("estimated_cost_usd")),
    }
    # The rules arm has no provider or model by design; the trial-level
    # declaration carries them. Resources and budgets must match across arms
    # (already enforced by ``budget_parity``).
    controller = _object(trial_dir / "controller.json")
    declared = {key: controller.get(key) for key in ("provider", "model")}
    if not declared["provider"] or not declared["model"]:
        declared = {key: (evidence["llm"]["run_meta"] or {}).get(key) for key in ("provider", "model")}
    shared = evidence["rules"]["run_meta"] or {}
    configuration = {**declared,
                     "resource_manifest_sha256": shared.get("resource_manifest_sha256"),
                     "budgets": shared.get("budgets")}
    return {
        "trial_dir": str(trial_dir), "complete": True,
        "comparison": comparisons[0].name,
        "experiment": experiment,
        "trial_id": experiment.get("trial_id") or planned.get("trial_id"),
        "family_id": experiment.get("family_id"),
        "repetition": planned.get("repetition"),
        "intentional_flaws": planned.get("intentional_flaws"),
        "policy_outcomes": {policy: arms[policy]["evaluation"].get("outcome")
                            for policy in ("rules", "llm")},
        "arms": arms,
        "deltas": deltas,
        "admission": pair_admission(evidence),
        "configuration": configuration,
    }


def _descriptive(records):
    """Per family and posture, per policy: rates and means with denominators."""
    groups = defaultdict(lambda: defaultdict(list))
    for record in records:
        posture = "f1" if record.get("intentional_flaws") else "f0"
        for policy in ("rules", "llm"):
            groups[(record.get("family_id"), posture)][policy].append(record)
    result = {}
    for (family, posture), by_policy in sorted(groups.items()):
        entry = {}
        for policy, records in sorted(by_policy.items()):
            verdicts = [r["arms"][policy]["evaluation"].get("success") for r in records]
            known = [bool(v) for v in verdicts if v is not None]
            tool_calls = [r["arms"][policy]["metrics"].get("tool_calls") for r in records]
            wall_clock = [r["arms"][policy]["metrics"].get("wall_clock_s") for r in records]
            entry[policy] = {
                "trials": len(records),
                "evaluated": len(known),
                "successes": sum(known),
                "success_rate": sum(known) / len(known) if known else None,
                "mean_tool_calls": statistics.fmean(
                    [v for v in tool_calls if _number(v) is not None]) if any(
                    _number(v) is not None for v in tool_calls) else None,
                "mean_wall_clock_s": statistics.fmean(
                    [v for v in wall_clock if _number(v) is not None]) if any(
                    _number(v) is not None for v in wall_clock) else None,
            }
        result.setdefault(family, {})[posture] = entry
    return result


def summarize_experiments(roots, *, campaign_id=None, delta_threshold=0.05,
                          minimum_families=2, minimum_repetitions=3,
                          strict_v3_metrics_adopted=False, seed=DEFAULT_SEED):
    """Summarize one or more V2 experiment roots without executing anything."""
    records, incomplete = [], []
    for root in roots:
        root = Path(root)
        for trial_dir in sorted((root / "trials").glob("*")):
            if not trial_dir.is_dir():
                continue
            record = read_trial(trial_dir)
            (records if record["complete"] else incomplete).append(record)
    included = [record for record in records if record["admission"]["met"]]
    excluded = [record for record in records if not record["admission"]["met"]]
    families = defaultdict(list)
    repetitions = defaultdict(set)
    for record in included:
        families[record["family_id"]].append(record["deltas"])
        if record.get("repetition") is not None:
            repetitions[record["family_id"]].add(record["repetition"])
    repetitions = {family: len(values) for family, values in repetitions.items()}
    admission = campaign_admission(
        [record["admission"] for record in included], families=len(families),
        repetitions=repetitions,
        configurations=[record["configuration"] for record in included] if included else [],
        strict_v3_metrics_adopted=strict_v3_metrics_adopted,
        minimum_families=minimum_families, minimum_repetitions=minimum_repetitions)
    groups = defaultdict(list)
    for record in included:
        groups[json.dumps(record["configuration"], sort_keys=True)].append(record)
    by_configuration = {}
    for key, group_records in sorted(groups.items()):
        group_families = defaultdict(list)
        for record in group_records:
            group_families[record["family_id"]].append(record["deltas"])
        by_configuration[key] = {
            "configuration": group_records[0]["configuration"],
            "included_trials": len(group_records),
            "families": sorted(group_families),
            "inference": family_inference(dict(group_families), V2_METRICS,
                                          delta_threshold=delta_threshold, seed=seed),
        }
    # A model panel is not one uniform configuration: pool nothing across it.
    if len(by_configuration) == 1:
        inference = next(iter(by_configuration.values()))["inference"]
    else:
        inference = {"available": False, "metrics": {}, "delta_threshold": delta_threshold,
                     "reason": "Several configurations; read by_configuration instead",
                     "method": "paired bootstrap over family means (percentile 95% CI), Holm across metrics"}
    return {
        "schema_version": SCHEMA_VERSION,
        "campaign_id": campaign_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "roots": [str(Path(root).resolve()) for root in roots],
        "declared_configuration": {"provider": PROVIDER, "model_panel": list(MODEL_PANEL)},
        "scope": ("Calibration verdicts mapped to paired per-family deltas; strict-v3 admission "
                  "requires an explicit metrics amendment"),
        "planned_trials": len(records) + len(incomplete),
        "evaluated_trials": len(records),
        "included_trials": len(included),
        "excluded_trials": len(excluded) + len(incomplete),
        "families": sorted(families),
        "repetitions_per_family": dict(sorted(repetitions.items())),
        "descriptive": _descriptive(included),
        "by_configuration": by_configuration,
        "inference": inference,
        "admission": admission,
        "excluded": [{"trial_id": record.get("trial_id"), "family_id": record.get("family_id"),
                      "unmet": record["admission"]["unmet"]} for record in excluded],
        "incomplete": [{"trial_dir": record["trial_dir"], "problem": record["problem"]}
                       for record in incomplete],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Summarize V2 experiment roots offline")
    parser.add_argument("--root", type=Path, action="append", required=True,
                        help="V2 experiment root; repeat to combine independent families")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--campaign-id")
    parser.add_argument("--delta-threshold", type=float, default=0.05)
    parser.add_argument("--minimum-families", type=int, default=2)
    parser.add_argument("--minimum-repetitions", type=int, default=3)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args(argv)
    try:
        if args.minimum_families < 2:
            raise ValueError("Paired inference requires at least two independent families")
        result = summarize_experiments(
            args.root, campaign_id=args.campaign_id, delta_threshold=args.delta_threshold,
            minimum_families=args.minimum_families,
            minimum_repetitions=args.minimum_repetitions, seed=args.seed)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
                               encoding="utf-8")
    except (OSError, ValueError, TypeError, KeyError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
