"""V2 campaign identity, admission gate and family-level summary.

The V2 pilot harnesses emit calibration verdicts (``success``,
``evidence_only_not_admitted``), not strict-v3 TP/FP/FN. Two contracts must
therefore stay separate:

* ``pair_admission`` / ``campaign_admission`` compute admission from observable
  conditions and name every unmet one, instead of hardcoding ``False``.
* ``summarize_experiments`` maps the calibration verdicts onto paired
  per-family deltas and hands them to ``src.benchmark.inference``.

The design distinguishes the vulnerable posture F1 (``Δ1``) from the protected
posture F0 (``Δ0``). They are never pooled: inference and descriptive rates are
computed separately per posture. Success rates use the planned denominator
``K / N_planned`` and the descriptive bounds ``[K/N, (K+N-M)/N]`` where ``M``
counts planned but unobservable outcomes. A missing outcome is never zero and
never silently shrinks the denominator.

Nothing here deploys, executes, uploads or edits an existing record.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import statistics

from src.agent.audit_experiment import digest
from src.benchmark.inference import DEFAULT_SEED, family_inference

SCHEMA_VERSION = "v2-campaign-v2"
PROVIDER = "ollama-umons"
# The UMONS catalogue exposes one dense model and one mixture-of-experts model.
# Both are audited under the same prompts, tools and budgets.
MODEL_PANEL = ("qwen3.8:27b", "gemma4:26b-a4b-it-q4_K_M")
DEFAULT_MODEL = MODEL_PANEL[0]
V2_METRICS = ("task_success", "tool_calls", "wall_clock_s", "llm_estimated_cost_usd")
POSTURES = ("f0", "f1")
PAIR_CONDITIONS = ("paired_execution_complete", "identity_present", "run_meta_present",
                   "budget_parity", "resource_parity", "preflight_attested",
                   "evidence_integrity", "evaluation_available")
CAMPAIGN_CONDITIONS = ("pair_conditions", "collection_complete",
                       "strict_v3_metrics_adopted", "configuration_uniformity",
                       "independent_families", "posture_coverage",
                       "minimum_repetitions", "unique_trials")


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


def trial_identity(campaign_id, scenario_id, flaws, repetition, *, configuration_id=None):
    """``experiment`` block written into every ``run_meta.json``."""
    posture = "f1" if flaws else "f0"
    trial = f"{scenario_id}-{posture}-r{int(repetition)}"
    identity = {"id": campaign_id, "trial_id": trial, "family_id": scenario_id,
                "posture": posture, "repetition": int(repetition), "instance_id": trial}
    if configuration_id:
        identity["configuration_id"] = str(configuration_id)
    return identity


def arm_order(flaws, repetition):
    """Counterbalanced arm order within a posture across repetitions."""
    base = ["rules", "llm"] if not flaws else ["llm", "rules"]
    return base if int(repetition) % 2 == 1 else list(reversed(base))


def planned_cases(repetitions):
    """Interleave F0 and F1 by repetition so machine drift is not a posture."""
    return [(flaws, repetition) for repetition in range(1, int(repetitions) + 1)
            for flaws in (0, 1)]


def _condition(conditions, name, met, reason):
    conditions[name] = {"met": bool(met), "reason": None if met else reason}


def _identity_valid(experiment, planned):
    """The experiment block and the planned posture must agree."""
    if not isinstance(experiment, dict) or not isinstance(planned, dict):
        return False
    identity = experiment
    if not all(identity.get(key) for key in ("id", "trial_id", "family_id", "posture")):
        return False
    posture = identity.get("posture")
    flaws = planned.get("intentional_flaws")
    if posture not in POSTURES or flaws not in (0, 1):
        return False
    if posture != ("f1" if int(flaws) else "f0"):
        return False
    if planned.get("repetition") is not None and identity.get("repetition") is not None:
        return int(planned["repetition"]) == int(identity["repetition"])
    return True


def pair_admission(arms, *, experiment=None, planned=None):
    """Evaluate the per-pair conditions from one trial's own artifacts.

    ``arms`` maps ``rules``/``llm`` to a dict with any of ``run_meta``,
    ``evaluation`` and ``preflight``. Provider usage accounting is *not* an
    admission condition: a provider failure remains a published non-success and
    only the cost/token metrics become unknown.
    """
    conditions = {}
    present = set(arms) == {"rules", "llm"}
    _condition(conditions, "paired_execution_complete", present,
               "Both decision arms must be present")
    _condition(conditions, "identity_present", _identity_valid(experiment, planned),
               "experiment identity and planned posture/repetition must be present and agree")
    metas = {policy: (arms.get(policy) or {}).get("run_meta") or {} for policy in ("rules", "llm")}
    _condition(conditions, "run_meta_present",
               present and all(metas[policy] and metas[policy].get("experiment")
                               for policy in ("rules", "llm")),
               "run_meta.json with its experiment block is required for each arm")
    budgets = [metas[policy].get("budgets") for policy in ("rules", "llm")]
    _condition(conditions, "budget_parity",
               present and budgets[0] is not None and budgets[0] == budgets[1],
               "Both arms must declare identical budgets")
    manifests = [metas[policy].get("resource_manifest_sha256") for policy in ("rules", "llm")]
    _condition(conditions, "resource_parity",
               present and manifests[0] is not None and manifests[0] == manifests[1],
               "Both arms must share one resource manifest")
    attestations = [((arms.get(policy) or {}).get("preflight") or {}) for policy in ("rules", "llm")]
    briefings = [attestations[index].get("briefing_sha256") for index in (0, 1)]
    metas_briefings = [metas[policy].get("briefing_sha256") for policy in ("rules", "llm")]
    _condition(conditions, "preflight_attested",
               present and all(item.get("status") == "valid" for item in attestations)
               and briefings[0] is not None and briefings[0] == briefings[1]
               and briefings == metas_briefings,
               "Each arm needs a valid preflight attestation bound to the pair briefing")
    _condition(conditions, "evidence_integrity",
               present and all(metas[policy].get("evidence_integrity_failed") is False
                               for policy in ("rules", "llm")),
               "Evidence archiving must not have failed")
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
                       minimum_repetitions=3, excluded=0, incomplete=0,
                       duplicates=0):
    """Combine per-pair conditions with the campaign-level requirements.

    ``repetitions`` maps family_id -> posture -> observed repetition count.
    """
    conditions = {}
    _condition(conditions, "pair_conditions",
               bool(pairs) and all(pair.get("met") is True for pair in pairs),
               "Every included pair must meet its own conditions")
    _condition(conditions, "collection_complete", excluded == 0 and incomplete == 0,
               f"The plan must be complete; excluded={excluded}, incomplete={incomplete}")
    _condition(conditions, "strict_v3_metrics_adopted", strict_v3_metrics_adopted,
               "Calibration verdicts are not strict-v3 TP/FP/FN; an amendment is required")
    _condition(conditions, "configuration_uniformity",
               bool(configurations) and all(item == configurations[0] for item in configurations),
               "Every included arm must share provider, model, resources and budgets")
    _condition(conditions, "independent_families", int(families) >= minimum_families,
               f"At least {minimum_families} independent families are required; got {families}")
    counts = [count for family in repetitions.values() for count in family.values()] \
        if repetitions else []
    coverage = bool(repetitions) and all(
        all(family.get(posture, 0) >= minimum_repetitions for posture in POSTURES)
        for family in repetitions.values())
    _condition(conditions, "posture_coverage", coverage,
               "Each family needs F0 and F1 repetitions between the declared bounds")
    fewest = min(counts) if counts else 0
    _condition(conditions, "minimum_repetitions", fewest >= minimum_repetitions,
               f"Each family and posture needs at least {minimum_repetitions} repetitions; "
               f"lowest is {fewest}")
    _condition(conditions, "unique_trials", duplicates == 0,
               f"Trial identities must be unique; {duplicates} duplicate(s) found")
    unmet = [name for name in CAMPAIGN_CONDITIONS if not conditions[name]["met"]]
    return {"mt_admissible": not unmet, "conditions": conditions, "unmet": unmet}


def _load(path):
    """Return ``(value, problem)``; an unreadable or invalid file is not empty."""
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}, "missing"
    except (OSError, ValueError) as exc:
        return {}, f"invalid: {type(exc).__name__}"
    return (value, None) if isinstance(value, dict) else ({}, "invalid: not an object")


def _object(path):
    return _load(path)[0]


def _number(value):
    if isinstance(value, bool):
        return int(value)
    return float(value) if type(value) in (int, float) else None


def _delta(left, right):
    return None if left is None or right is None else left - right


def _run_directory(trial_dir, policy, root):
    """Resolve ``<policy>_dir.txt`` without following it outside the collection."""
    pointer = trial_dir / f"{policy}_dir.txt"
    if not pointer.is_file():
        return None, f"missing {policy} run pointer"
    text = pointer.read_text(encoding="utf-8").strip()
    if not text:
        return None, f"empty {policy} run pointer"
    path = Path(text)
    if not path.is_absolute() or path.is_symlink():
        return None, f"unconfined {policy} run pointer"
    resolved = path.resolve()
    if root is not None and not resolved.is_relative_to(Path(root).resolve()):
        return None, f"{policy} run pointer escapes the experiment root"
    if not (resolved / "run_meta.json").is_file():
        return None, f"{policy} run directory has no run_meta.json"
    return resolved, None


def read_trial(trial_dir, *, root=None):
    """Read one V2 trial directory; never invent missing measurements."""
    trial_dir = Path(trial_dir)
    comparisons = sorted(trial_dir.glob("comparison-*.json"))
    if len(comparisons) != 1:
        return {"trial_dir": str(trial_dir), "complete": False,
                "problem": "expected exactly one comparison file"}
    comparison, problem = _load(comparisons[0])
    if problem:
        return {"trial_dir": str(trial_dir), "complete": False,
                "problem": f"comparison file is {problem}"}
    planned, planned_problem = _load(trial_dir / "planned.json")
    if planned_problem:
        return {"trial_dir": str(trial_dir), "complete": False,
                "problem": f"planned.json is {planned_problem}"}
    experiment = {}
    arms, evidence, evaluations, problems = {}, {}, {}, []
    for policy in ("rules", "llm"):
        run_dir, pointer_problem = _run_directory(trial_dir, policy, root)
        if pointer_problem:
            problems.append(pointer_problem)
        run_meta, meta_problem = _load(run_dir / "run_meta.json") if run_dir else ({}, None)
        if meta_problem:
            problems.append(f"{policy} run_meta.json is {meta_problem}")
        attestation, attestation_problem = _load(trial_dir / "preflight" / policy / "attestation.json")
        if attestation_problem:
            problems.append(f"{policy} attestation is {attestation_problem}")
        arm = (comparison.get("arms") or {}).get(policy) or {}
        experiment = experiment or run_meta.get("experiment") or planned.get("experiment") or {}
        arms[policy] = {"metrics": arm.get("metrics") or {}, "evaluation": arm.get("evaluation") or {}}
        evaluations[policy] = arm.get("evaluation") or {}
        evidence[policy] = {"run_meta": run_meta, "evaluation": arm.get("evaluation"),
                            "preflight": attestation,
                            "usage_complete": (arm.get("metrics") or {}).get("usage_complete")}
    if problems:
        return {"trial_dir": str(trial_dir), "complete": False,
                "problem": "; ".join(sorted(set(problems)))}
    deltas = {
        "task_success": _delta(_number(evaluations["llm"].get("success")),
                               _number(evaluations["rules"].get("success"))),
        "tool_calls": _delta(_number(arms["llm"]["metrics"].get("tool_calls")),
                             _number(arms["rules"]["metrics"].get("tool_calls"))),
        "wall_clock_s": _delta(_number(arms["llm"]["metrics"].get("wall_clock_s")),
                               _number(arms["rules"]["metrics"].get("wall_clock_s"))),
        "llm_estimated_cost_usd": _number(arms["llm"]["metrics"].get("estimated_cost_usd")),
    }
    # The rules arm has no provider or model by design; the trial-level
    # declaration carries them. Resources, budgets and the implementation
    # manifest must match across arms (enforced by the parity conditions).
    controller = _object(trial_dir / "controller.json")
    declared = {key: controller.get(key) for key in ("provider", "model")}
    if not declared["provider"] or not declared["model"]:
        declared = {key: (evidence["llm"]["run_meta"] or {}).get(key) for key in ("provider", "model")}
    shared = evidence["rules"]["run_meta"] or {}
    configuration = {**declared,
                     "git_commit": shared.get("git_commit"),
                     "resource_manifest_sha256": shared.get("resource_manifest_sha256"),
                     "implementation_sha256": shared.get("implementation_sha256"),
                     "budgets": shared.get("budgets")}
    posture = experiment.get("posture") or ("f1" if planned.get("intentional_flaws") else "f0")
    return {
        "trial_dir": str(trial_dir), "complete": True,
        "comparison": comparisons[0].name,
        "experiment": experiment,
        "trial_id": experiment.get("trial_id") or planned.get("trial_id"),
        "family_id": experiment.get("family_id") or planned.get("scenario_id"),
        "posture": posture,
        "repetition": planned.get("repetition"),
        "intentional_flaws": planned.get("intentional_flaws"),
        "policy_outcomes": {policy: arms[policy]["evaluation"].get("outcome")
                            for policy in ("rules", "llm")},
        "arms": arms,
        "deltas": deltas,
        "admission": pair_admission(evidence, experiment=experiment, planned=planned),
        "configuration": configuration,
    }


def _plan(root):
    plan = _object(Path(root) / "plan.json")
    scenario, repetitions = plan.get("scenario_id"), plan.get("repetitions")
    if scenario and isinstance(repetitions, int) and repetitions > 0:
        return scenario, repetitions
    return None, None


def _descriptive(records, planned):
    """Planned-denominator rates, bounds and guards per configuration/posture."""
    groups = defaultdict(list)
    for record in records:
        key = json.dumps(record["configuration"], sort_keys=True)
        groups[(key, record.get("family_id"), record.get("posture"))].append(record)
    result = {}
    for (config, family, posture), group in sorted(groups.items(), key=lambda item: str(item[0])):
        plan = planned.get(family) or {}
        planned_pairs = plan.get(posture) or len(group)
        denominator_source = "plan" if plan else "observed"
        entry = {}
        for policy in ("rules", "llm"):
            verdicts = [r["arms"][policy]["evaluation"].get("success") for r in group]
            known = [bool(v) for v in verdicts if v is not None]
            tool_calls = [r["arms"][policy]["metrics"].get("tool_calls") for r in group]
            wall_clock = [r["arms"][policy]["metrics"].get("wall_clock_s") for r in group]
            cost = [r["deltas"].get("llm_estimated_cost_usd") for r in group] if policy == "llm" else []
            false_positives = [r["arms"][policy]["evaluation"].get("false_positive") for r in group]
            controls = [r["arms"][policy]["evaluation"].get("control_proven") for r in group]
            successes = sum(known)
            unobservable = max(0, planned_pairs - len(known))
            entry[policy] = {
                "planned": planned_pairs,
                "denominator_source": denominator_source,
                "observed_pairs": len(group),
                "evaluated": len(known),
                "unobservable": unobservable,
                "successes": successes,
                "observed_rate": successes / len(known) if known else None,
                "planned_rate": successes / planned_pairs if planned_pairs else None,
                "success_bounds": ([successes / planned_pairs,
                                    (successes + planned_pairs - len(known)) / planned_pairs]
                                   if planned_pairs else None),
                "mean_tool_calls": statistics.fmean(
                    [v for v in tool_calls if _number(v) is not None]) if any(
                    _number(v) is not None for v in tool_calls) else None,
                "mean_wall_clock_s": statistics.fmean(
                    [v for v in wall_clock if _number(v) is not None]) if any(
                    _number(v) is not None for v in wall_clock) else None,
                "mean_llm_estimated_cost_usd": (statistics.fmean(
                    [v for v in cost if v is not None]) if any(v is not None for v in cost) else None),
                "false_positives": sum(1 for value in false_positives if value is True),
                "false_positive_rate": (sum(1 for value in false_positives if value is True) / planned_pairs
                                        if posture == "f0" and planned_pairs else None),
                "controls_proven": sum(1 for value in controls if value is True),
                "control_rate": (sum(1 for value in controls if value is True) / len(group)
                                 if group else None),
            }
        result.setdefault(config, {}).setdefault(family, {})[posture] = entry
    return result


def _repetition_counts(records):
    counts = defaultdict(lambda: defaultdict(set))
    for record in records:
        if record.get("repetition") is not None:
            counts[record.get("family_id")][record.get("posture")].add(record["repetition"])
    return {family: {posture: len(values) for posture, values in sorted(postures.items())}
            for family, postures in sorted(counts.items())}


def summarize_experiments(roots, *, campaign_id=None, delta_threshold=None,
                          minimum_families=2, minimum_repetitions=3,
                          strict_v3_metrics_adopted=False, seed=DEFAULT_SEED):
    """Summarize one or more V2 experiment roots without executing anything."""
    record_pairs, incomplete, duplicates, planned = [], [], [], {}
    seen = set()
    resolved_roots = []
    for root in roots:
        root = Path(root).resolve()
        if root in resolved_roots:
            continue
        resolved_roots.append(root)
        scenario, plan_repetitions = _plan(root)
        if scenario:
            planned[scenario] = {posture: plan_repetitions for posture in POSTURES}
        for trial_dir in sorted((root / "trials").glob("*")):
            if not trial_dir.is_dir():
                continue
            record = read_trial(trial_dir, root=root)
            if not record["complete"]:
                incomplete.append(record)
                continue
            # A model panel is two configurations; the same trial name in two
            # configurations is not a duplicate. The same configuration twice is.
            key = (record["experiment"].get("id") or campaign_id,
                   record["experiment"].get("configuration_id"),
                   record.get("trial_id"))
            if key in seen:
                duplicates.append({"trial_id": record.get("trial_id"),
                                   "trial_dir": record["trial_dir"]})
                continue
            seen.add(key)
            record_pairs.append(record)
    included = [record for record in record_pairs if record["admission"]["met"]]
    excluded = [record for record in record_pairs if not record["admission"]["met"]]
    repetitions = _repetition_counts(included)
    admission = campaign_admission(
        [record["admission"] for record in included], families=len(repetitions),
        repetitions=repetitions,
        configurations=[record["configuration"] for record in included] if included else [],
        strict_v3_metrics_adopted=strict_v3_metrics_adopted,
        minimum_families=minimum_families, minimum_repetitions=minimum_repetitions,
        excluded=len(excluded), incomplete=len(incomplete), duplicates=len(duplicates))
    groups = defaultdict(list)
    for record in included:
        groups[json.dumps(record["configuration"], sort_keys=True)].append(record)
    by_configuration = {}
    for key, group_records in sorted(groups.items()):
        posture_inference = {}
        for posture in POSTURES:
            family_deltas = defaultdict(list)
            for record in group_records:
                if record.get("posture") == posture:
                    family_deltas[record["family_id"]].append(record["deltas"])
            posture_inference[posture] = family_inference(
                dict(family_deltas), V2_METRICS, delta_threshold=delta_threshold, seed=seed)
            posture_inference[posture]["status"] = "exploratory"
        by_configuration[key] = {
            "configuration": group_records[0]["configuration"],
            "included_trials": len(group_records),
            "families": sorted({record["family_id"] for record in group_records}),
            "inference": posture_inference,
        }
    return {
        "schema_version": SCHEMA_VERSION,
        "campaign_id": campaign_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "roots": [str(root) for root in resolved_roots],
        "declared_configuration": {"provider": PROVIDER, "model_panel": list(MODEL_PANEL)},
        "scope": ("Calibration verdicts mapped to paired per-family deltas; strict-v3 admission "
                  "requires an explicit metrics amendment. Inference is exploratory, separate "
                  "per posture, and uses planned denominators for descriptive rates."),
        "planned_trials": sum(sum(family.values()) for family in planned.values()),
        "observed_trials": len(record_pairs) + len(incomplete) + len(duplicates),
        "evaluated_trials": len(record_pairs),
        "included_trials": len(included),
        "excluded_trials": len(excluded) + len(incomplete) + len(duplicates),
        "families": sorted(repetitions),
        "repetitions_per_family": repetitions,
        "descriptive": _descriptive(included, planned),
        "by_configuration": by_configuration,
        "inference": ("See by_configuration; postures F0 and F1 are never pooled"),
        "admission": admission,
        "excluded": [{"trial_id": record.get("trial_id"), "family_id": record.get("family_id"),
                      "unmet": record["admission"]["unmet"]} for record in excluded],
        "incomplete": [{"trial_dir": record["trial_dir"], "problem": record["problem"]}
                       for record in incomplete],
        "duplicates": duplicates,
    }


def _write_atomic(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
                         encoding="utf-8")
    os.replace(temporary, path)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Summarize V2 experiment roots offline")
    parser.add_argument("--root", type=Path, action="append", required=True,
                        help="V2 experiment root; repeat to combine independent families")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--campaign-id")
    parser.add_argument("--delta-threshold", type=float, default=None,
                        help="Optional unfrozen descriptive threshold; no default is assumed")
    parser.add_argument("--minimum-families", type=int, default=2)
    parser.add_argument("--minimum-repetitions", type=int, default=3)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args(argv)
    try:
        if args.minimum_families < 2:
            raise ValueError("Paired inference requires at least two independent families")
        if args.minimum_repetitions < 1:
            raise ValueError("minimum repetitions must be at least one")
        if args.delta_threshold is not None and args.delta_threshold <= 0:
            raise ValueError("delta threshold must be positive when provided")
        for root in args.root:
            if not root.is_dir() or not (root / "trials").is_dir():
                raise ValueError(f"Experiment root has no trials directory: {root}")
        result = summarize_experiments(
            args.root, campaign_id=args.campaign_id, delta_threshold=args.delta_threshold,
            minimum_families=args.minimum_families,
            minimum_repetitions=args.minimum_repetitions, seed=args.seed)
        _write_atomic(args.output, result)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
