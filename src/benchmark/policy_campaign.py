"""Describe every planned policy trial without deploying or executing any audit."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
import math
from pathlib import Path
import re
from statistics import mean

import yaml

from src.agent.audit_experiment import digest, positive_limit
from src.benchmark.comparability import configuration_identity
from src.benchmark.compare_policies import compare_runs

POLICIES = ("rules", "llm")
RESOURCES = ("total_cost_usd", "wall_clock_duration_s", "total_tool_calls")
QUALITY = ("confirmed.true_positives", "confirmed.false_positives", "confirmed.false_negatives",
           "confirmed.precision", "confirmed.recall", "confirmed.f1",
           "specificity", "negative_control_specificity", "negative_control_violations")
CONFIG_FIELDS = {"provider", "model", "rules_version", "resource_manifest_sha256",
                 "max_tool_calls", "max_duration_s", "max_cost_usd", "execution_profile"}


def _number(value):
    return value if type(value) in (int, float) and math.isfinite(value) and value >= 0 else None


def _object(path):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("expected a JSON object")
        return value, None
    except (OSError, ValueError) as exc:
        return {}, f"{path.name}: {exc}"


def _path(base, value):
    return (base / value).resolve() if value is not None else None


def load_manifest(path: Path):
    data, problem = _object(path)
    if problem:
        raise ValueError(problem)
    if data.get("schema_version") != 1 or type(data.get("schema_version")) is not int:
        raise ValueError("Expected campaign schema_version 1")
    if not isinstance(data.get("campaign_id"), str) or not data["campaign_id"].strip():
        raise ValueError("campaign_id is required")
    configuration = data.get("configuration")
    if not isinstance(configuration, dict) or set(configuration) - CONFIG_FIELDS:
        raise ValueError("configuration must contain supported run metadata fields")
    for key, value in configuration.items():
        if key in {"max_tool_calls", "max_duration_s", "max_cost_usd"}:
            positive_limit(value, key, integer=key == "max_tool_calls")
            if value is None and key != "max_cost_usd":
                raise ValueError(f"{key} cannot be null")
        elif not isinstance(value, str) or not value.strip():
            raise ValueError(f"configuration {key} must be nonempty text")
        elif key == "resource_manifest_sha256" and not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("resource_manifest_sha256 must be a SHA-256 digest")
        elif key == "execution_profile" and value != "full":
            raise ValueError("Policy experiments require the full profile")
    if not isinstance(data.get("trials"), list) or not data["trials"]:
        raise ValueError("List every planned paired trial in trials")
    ids, runs = set(), set()
    for trial in data["trials"]:
        if not isinstance(trial, dict):
            raise ValueError("Each trial must be an object")
        for key in ("trial_id", "family_id", "instance_id"):
            if not isinstance(trial.get(key), str) or not trial[key].strip():
                raise ValueError(f"Trial {key} is required")
        if trial["trial_id"] in ids:
            raise ValueError("Duplicate trial_id")
        ids.add(trial["trial_id"])
        if trial.get("order") not in (["rules", "llm"], ["llm", "rules"]):
            raise ValueError("order must contain rules and llm once each")
        if trial.get("ground_truth") is not None and (
                not isinstance(trial["ground_truth"], str) or not trial["ground_truth"].strip()):
            raise ValueError("ground_truth must be a path or null")
        arms = trial.get("arms")
        if not isinstance(arms, dict) or set(arms) != set(POLICIES):
            raise ValueError("Each planned pair must retain both arms")
        for arm in arms.values():
            if not isinstance(arm, dict):
                raise ValueError("Each arm must be an object")
            run_dir = arm.get("run_dir")
            if run_dir is not None:
                if not isinstance(run_dir, str) or not run_dir.strip():
                    raise ValueError("run_dir must be a nonempty path or null")
                resolved = _path(path.parent, run_dir)
                if resolved in runs:
                    raise ValueError("A run directory cannot be reused across planned arms")
                runs.add(resolved)
            preflight = arm.get("preflight")
            if not isinstance(preflight, dict) or preflight.get("status") not in ("pending", "valid", "invalid"):
                raise ValueError("Each arm requires preflight status pending, valid or invalid")
            ref = preflight.get("evidence_ref")
            if ref is not None and (not isinstance(ref, str) or not ref.strip()):
                raise ValueError("evidence_ref must be a nonempty path or null")
            if preflight["status"] != "pending" and (not isinstance(ref, str) or not ref.strip()):
                raise ValueError("A preflight declaration requires an evidence_ref path")
    return data


def _observe_arm(base, campaign, trial, policy, arm, evaluated):
    run_dir = _path(base, arm.get("run_dir"))
    meta, cost, problems = {}, {}, []
    if run_dir is not None:
        meta, issue = _object(run_dir / "run_meta.json")
        if issue:
            problems.append(issue)
        cost, issue = _object(run_dir / "cost_summary.json")
        if issue:
            problems.append(issue)
    metrics = {key: _number(cost.get(key)) for key in RESOURCES}
    preflight = arm["preflight"]
    ref = _path(base, preflight.get("evidence_ref"))
    attested = ref is not None and ref.is_file()
    preflight_hash = None
    if attested:
        try:
            preflight_hash = hashlib.sha256(ref.read_bytes()).hexdigest()
        except OSError:
            attested = False
    expected = {"id": campaign["campaign_id"], **{key: trial[key] for key in ("trial_id", "family_id", "instance_id")}}
    identity_problems = []
    if meta:
        experiment = meta.get("experiment")
        if not isinstance(experiment, dict) or any(experiment.get(key) != value for key, value in expected.items()):
            identity_problems.append("Run experiment does not match its planned trial")
        if meta.get("decision_policy") != policy:
            identity_problems.append("Wrong decision policy")
        for key, value in campaign["configuration"].items():
            if policy == "rules" and key in {"model", "provider"}:
                continue
            if meta.get(key) != value:
                identity_problems.append(f"Run differs from planned {key}")
    problems.extend(identity_problems)
    evaluation_problems = list(evaluated.get("problems", ["Evaluation unavailable"]))
    problems.extend(evaluation_problems)
    status = meta.get("status", "unknown")
    if not isinstance(status, str):
        problems.append("Malformed run status")
        status = "unknown"
    over_budget = any(
        metrics[metric] is not None and _number(meta.get(limit)) is not None
        and metrics[metric] > meta[limit]
        for metric, limit in (("total_tool_calls", "max_tool_calls"),
                              ("wall_clock_duration_s", "max_duration_s"),
                              ("total_cost_usd", "max_cost_usd"))
    )
    if preflight["status"] == "invalid" and attested:
        # Once an audit exists this cannot silently excuse a system failure.
        outcome = "protocol_violation" if meta or (run_dir and (run_dir / "tool_calls.jsonl").exists()) else "environment_invalid"
    elif run_dir is None:
        outcome = "not_run"
    elif not meta:
        outcome = "missing_artifacts"
    elif identity_problems:
        outcome = "configuration_mismatch"
    elif status in {"budget_exceeded", "stopped", "failed", "partial"}:
        outcome = status
    elif over_budget:
        outcome = "budget_exceeded"
    elif status in {"running", "pending"}:
        outcome = "running"
    elif preflight["status"] != "valid" or not attested:
        outcome = "environment_unverified"
    elif status == "completed" and not problems and meta.get("usage_status") == "completed":
        outcome = "usable"
    else:
        outcome = "completed_unusable" if status == "completed" else "unknown"
    if preflight["status"] != "pending" and not attested:
        problems.append("Preflight evidence file is unavailable")
    evidence_metrics = evaluated.get("metrics", {})
    phases = cost.get("phases")
    pricing_sources = sorted({str(p["pricing_source"]) for p in phases
                              if isinstance(p, dict) and p.get("pricing_source")}) if isinstance(phases, list) else []
    return {
        "trial_id": trial["trial_id"], "family_id": trial["family_id"], "instance_id": trial["instance_id"],
        "policy": policy, "position": trial["order"].index(policy) + 1,
        "run_dir": str(run_dir) if run_dir else None, "run_status": status, "outcome": outcome,
        "preflight_status": preflight["status"], "preflight_sha256": preflight_hash,
        "usage_complete": meta.get("usage_status") == "completed",
        "cost_is_estimate": cost.get("cost_is_estimate"),
        "pricing_sources": pricing_sources,
        "resources": metrics, "quality": {key: evidence_metrics.get(key) for key in QUALITY},
        "problems": problems,
    }, meta


def summarize_campaign(path: Path):
    campaign = load_manifest(path)
    rows, pairs = [], []
    groups = defaultdict(lambda: defaultdict(list))
    group_configs = {}
    for trial in campaign["trials"]:
        truth = _path(path.parent, trial.get("ground_truth"))
        pair = {"comparable": False, "incomparability_reasons": ["Ground truth is not prepared"], "arms": {}}
        if truth is not None and truth.is_file():
            try:
                pair = compare_runs(*(_path(path.parent, trial["arms"][p].get("run_dir")) for p in POLICIES), truth)
            except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError) as exc:
                pair["incomparability_reasons"] = [f"Evaluation failed: {exc}"]
        observed, metadata = {}, {}
        for policy in POLICIES:
            row, meta = _observe_arm(path.parent, campaign, trial, policy, trial["arms"][policy], pair["arms"].get(policy, {}))
            observed[policy], metadata[policy] = row, meta
            rows.append(row)
        eligible = pair["comparable"] and all(row["outcome"] == "usable" for row in observed.values())
        pair["campaign_eligible"] = eligible
        pair["trial_id"] = trial["trial_id"]
        if eligible:
            identities = {p: {
                **configuration_identity(metadata[p], scoring_policy="strict-v3")[0],
                "runtime_unavailable_tools": metadata[p]["runtime_unavailable_tools"],
                "cve_source": metadata[p]["cve_source"],
            } for p in POLICIES}
            group = digest(identities)
            group_configs[group] = identities
            pair["configuration_group"] = group
            groups[group][trial["family_id"]].append(pair["delta_llm_minus_rules"])
        pairs.append(pair)
    summaries = {}
    for policy in POLICIES:
        selected = [row for row in rows if row["policy"] == policy]
        resources = {}
        for metric in RESOURCES:
            known = [row["resources"][metric] for row in selected if row["resources"][metric] is not None]
            complete = all(row["usage_complete"] and row["resources"][metric] is not None for row in selected)
            resources[metric] = {"sum_observed": sum(known) if known else None,
                                 "observed_runs": len(known), "planned_runs": len(selected),
                                 "complete_total": sum(known) if complete else None}
        counts = Counter(row["outcome"] for row in selected)
        summaries[policy] = {"planned": len(selected), "outcomes": dict(counts),
                             "usable_fraction_of_planned": counts["usable"] / len(selected), "resources": resources}
    technical = []
    for group, families in groups.items():
        family_rows = []
        for family, deltas in families.items():
            family_rows.append({"family_id": family, "evaluable_pairs": len(deltas), "delta_means": {
                key: {"mean": mean(values) if values else None, "pairs_with_value": len(values)}
                for key in (*QUALITY, *RESOURCES)
                for values in [[d[key] for d in deltas if d.get(key) is not None]]
            }})
        technical.append({"configuration_group": group, "configuration": group_configs[group], "families": family_rows})
    return {
        "schema_version": "policy-campaign-v1", "campaign_id": campaign["campaign_id"],
        "manifest_sha256": digest(campaign), "declared_configuration": campaign["configuration"],
        "unfixed_configuration_fields": sorted(CONFIG_FIELDS - set(campaign["configuration"])),
        "planned_pairs": len(pairs), "eligible_pairs": sum(p["campaign_eligible"] for p in pairs),
        "operational": summaries, "technical_on_eligible_pairs": technical, "trials": rows, "pairs": pairs,
        "uncertainty": {"available": False, "reason": "Descriptive pilot only; no independence or sample-size claim"},
        "environment_scope": "Preflight/reset is operator-declared; its file is hashed but not independently certified",
        "cost_scope": "Observed LLM accounting, including failed trials; no infrastructure or human cost estimate",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--csv", type=Path)
    args = parser.parse_args()
    try:
        destinations = [args.output.resolve(), *([args.csv.resolve()] if args.csv else [])]
        if args.manifest.resolve() in destinations or len(set(destinations)) != len(destinations):
            raise ValueError("Manifest, JSON output and CSV output must have distinct paths")
        result = summarize_campaign(args.manifest)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")
        if args.csv:
            args.csv.parent.mkdir(parents=True, exist_ok=True)
            fields = ["trial_id", "family_id", "instance_id", "policy", "position", "outcome", "run_status", "usage_complete", *RESOURCES, *QUALITY, "problems"]
            with args.csv.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
                writer.writeheader()
                for row in result["trials"]:
                    writer.writerow({**row, **row["resources"], **row["quality"], "problems": " | ".join(row["problems"])})
    except (OSError, ValueError, TypeError, KeyError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
