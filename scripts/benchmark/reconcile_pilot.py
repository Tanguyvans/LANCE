"""Reconcile downloaded Actions attempts, never execute audits or contact nato.

Inputs are local copies of the Actions inventory, logs and artifacts. Optional
API downloads are read locally to locate missing original run references. The
report contains operational fields only; raw evidence remains in output/.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
from pathlib import Path
import re


RUN = re.compile(r"20\d{2}-\d{2}-\d{2}_\d{6}")
TRIAL = re.compile(r"s(?:1|14|15|1h)-r[123]")
POLICIES = ("rules", "llm")
RESOURCE_FIELDS = ("total_tool_calls", "wall_clock_duration_s", "total_cost_usd")


def load(path):
    return json.loads(path.read_text())


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def runtime_lines(path):
    for line in path.read_text().splitlines():
        # Actions echoes shell source in ANSI colors before actual execution.
        if "\x1b[" in line:
            continue
        text = line.split("\t")[-1]
        match = re.match(r"(\d{4}-\d\d-\d\dT\S+Z) (.*)", text)
        if match:
            yield match.group(1), match.group(2)


def recoveries(root):
    path = root / "api-recovery.json"
    return {r["run"]: r for r in load(path)} if path.exists() else {}


def recovered_path(root, entry):
    return root / "recovered-runs" / entry["instance"] / entry["run"]


def describe_arm(root, policy, name, recovered, comparison):
    entry = recovered.get(name)
    arm = {"run": name, "api_recovered": bool(entry and not entry.get("not_found_on_api"))}
    published = comparison.get("arms", {}).get(policy, {})
    arm["published_status"] = published.get("status")
    arm["usage_complete"] = False
    arm["resources"] = {key: published.get("metrics", {}).get(key) for key in RESOURCE_FIELDS}
    arm["cost_is_estimate"] = (published.get("evaluation") or {}).get("cost_is_estimate")
    evaluation = published.get("evaluation") or {}
    arm["resource_manifest_sha256"] = evaluation.get("comparability_identity", {}).get("resource_manifest_sha256")
    if arm["api_recovered"]:
        path = recovered_path(root, entry)
        meta = load(path / "run_meta.json") if (path / "run_meta.json").is_file() else {}
        cost = load(path / "cost_summary.json") if (path / "cost_summary.json").is_file() else {}
        arm.update({"instance": entry["instance"], "recovered_status": meta.get("status"),
                    "resource_manifest_sha256": meta.get("resource_manifest_sha256"),
                    "cost_is_estimate": cost.get("cost_is_estimate"),
                    "usage_complete": meta.get("usage_status") == "completed",
                    "proof_files_present": {name: (path / name).is_file() for name in (
                        "run_meta.json", "audit_inventory.json", "tool_calls.jsonl", "04_exploitation.json")},
                    "resources": {key: cost.get(key) for key in RESOURCE_FIELDS}})
    return arm


def reconcile_attempt(root, item, recovered):
    rid, workflow = str(item["databaseId"]), item["workflow"]
    directory = root / "actions" / rid
    log = directory / "workflow.log"
    events = list(runtime_lines(log))
    trial = "s1-r1" if workflow == "pilot-smoke.yml" else None
    started, refs, arm_starts = [], {}, {}
    for date, text in events:
        found = re.match(r"trial=(s\S+) instance=", text)
        if found and TRIAL.fullmatch(found[1]):
            trial = found[1]
        found = re.fullmatch(r"== arm [12]: (rules|llm) ==", text)
        if found:
            started.append(found[1])
            arm_starts[found[1]] = datetime.fromisoformat(date.replace("Z", "+00:00"))
        found = re.fullmatch(r"rules_dir=(\S+) llm_dir=(\S+)", text)
        if found:
            refs = {p: Path(value).name for p, value in zip(POLICIES, found.groups())}
    corrected = {}
    for policy, start in arm_starts.items():
        if RUN.fullmatch(refs.get(policy, "")):
            continue
        # Match a recovered run to the arm's creation boundary, identity and
        # policy. Never select a later success by score or status.
        candidates = []
        for name, entry in recovered.items():
            if not RUN.fullmatch(name) or entry.get("trial_id") != trial or entry.get("policy") != policy:
                continue
            created = datetime.strptime(name, "%Y-%m-%d_%H%M%S").replace(tzinfo=timezone(timedelta(hours=2)))
            if abs((created - start).total_seconds()) <= 5:
                candidates.append(name)
        if len(candidates) == 1:
            corrected[policy] = {"published_reference": refs.get(policy), "recovered_run": candidates[0]}
            refs[policy] = candidates[0]
    comparison, comparison_path = {}, None
    if set(started) == set(POLICIES) and trial:
        for path in sorted((directory / "artifacts").rglob(f"comparison-{trial}.json")):
            candidate = load(path)
            matches = all(Path(candidate.get("arms", {}).get(p, {}).get("run_dir") or "").name == refs.get(p)
                          for p in POLICIES)
            # Retain the published result when a known bad reference was corrected.
            if matches or (corrected and all(Path(candidate.get("arms", {}).get(p, {}).get("run_dir") or "").name
                                            == corrected.get(p, {}).get("published_reference", refs.get(p)) for p in POLICIES)):
                if comparison_path is not None and sha256(path) != sha256(comparison_path):
                    raise ValueError("Conflicting comparisons for the same executed arms")
                comparison, comparison_path = candidate, path
    artifacts = load(directory / "artifacts-index.json")
    preflights = {}
    if trial:
        for policy in started:
            matches = list((directory / "artifacts").rglob(f"preflight-{trial}-{policy}.json"))
            if len(matches) == 1:
                preflights[policy] = {"source_path": matches[0].relative_to(root).as_posix(),
                                      "sha256": sha256(matches[0]), "declared_status": load(matches[0]).get("status"),
                                      "human_validated": False}
    return {
        "attempt_id": f"{rid}-{item['attempt']}", "github_run_id": item["databaseId"],
        "workflow": workflow, "created_at": item["createdAt"], "workflow_commit": item["headSha"],
        "workflow_conclusion": item["conclusion"], "url": item["url"], "trial_id": trial,
        "started_arms": started, "reference_corrections": corrected,
        "published_comparable": comparison.get("comparable"),
        "comparison_sha256": sha256(comparison_path) if comparison_path else None,
        "source_log_sha256": sha256(log),
        "source_artifacts": [{"id": a["id"], "name": a["name"]} for a in artifacts],
        "arms": {p: describe_arm(root, p, refs.get(p), recovered, comparison) for p in started},
        "preflights": preflights,
        "preflight_human_validated": False,
    }


def reconcile(root, plan):
    recovered = recoveries(root)
    attempts = [reconcile_attempt(root, item, recovered) for item in load(root / "actions-inventory.json")]
    attempts.sort(key=lambda r: (r["created_at"], r["attempt_id"]))
    recomputed_path = root / "recomputed-index.json"
    recomputed = {r["attempt_id"]: r for r in load(recomputed_path)} if recomputed_path.exists() else {}
    for attempt in attempts:
        attempt["recomputed_comparable"] = recomputed.get(attempt["attempt_id"], {}).get("recomputed")
    referenced = {a["run"] for r in attempts for a in r["arms"].values()}
    diagnostics = [{key: entry.get(key) for key in ("run", "instance", "trial_id", "policy", "status")}
                   for name, entry in sorted(recovered.items()) if name not in referenced and entry.get("trial_id")]
    for entry in diagnostics:
        cost_path = recovered_path(root, entry) / "cost_summary.json"
        cost = load(cost_path) if cost_path.exists() else {}
        entry["resources"] = {key: cost.get(key) for key in RESOURCE_FIELDS}
        entry["cost_is_estimate"] = cost.get("cost_is_estimate")
    inspections = []
    inventory_path = root / "inspections-inventory.json"
    for item in load(inventory_path) if inventory_path.exists() else []:
        log = root / "inspections" / str(item["databaseId"]) / "workflow.log"
        events = list(runtime_lines(log))
        start = datetime.fromisoformat(item["createdAt"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(events[-1][0].replace("Z", "+00:00")) if events else start
        executed = []
        for entry in diagnostics:
            created = datetime.strptime(entry["run"], "%Y-%m-%d_%H%M%S").replace(tzinfo=timezone(timedelta(hours=2)))
            if start <= created <= end and any(entry["run"] in text for _, text in events):
                executed.append(entry["run"])
                entry.setdefault("inspection_run_ids", []).append(item["databaseId"])
        inspections.append({"github_run_id": item["databaseId"], "created_at": item["createdAt"],
                            "conclusion": item["conclusion"], "url": item["url"],
                            "executed_diagnostic_runs": executed, "source_log_sha256": sha256(log)})
    trials = []
    for planned in plan["trials"]:
        relevant = [r for r in attempts if r["workflow"] == "pilot-campaign.yml" and r["trial_id"] == planned["trial_id"]]
        frozen = [r for r in relevant if len(r["arms"]) == 2 and all(
            a["resource_manifest_sha256"] == plan["configuration"]["resource_manifest_sha256"] for a in r["arms"].values())]
        trials.append({"trial_id": planned["trial_id"], "attempt_ids": [r["attempt_id"] for r in relevant],
                       "frozen_execution_attempts": [r["attempt_id"] for r in frozen],
                       "published_comparable_attempts": [r["attempt_id"] for r in frozen if r["published_comparable"] is True],
                       "status": "executed" if frozen else "not_executed_under_freeze"})
    # Retried trial IDs and cumulative copies must not count a run's costs twice.
    distinct = {p: {} for p in POLICIES}
    for attempt in attempts:
        for policy, arm in attempt["arms"].items():
            key = (arm.get("instance"), arm["run"]) if arm["run"] else (attempt["attempt_id"], policy)
            if key in distinct[policy]:
                raise ValueError("Run reused across execution attempts")
            distinct[policy][key] = arm
    resources = {}
    for policy in POLICIES:
        resources[policy] = {}
        for metric in RESOURCE_FIELDS:
            values = [a["resources"].get(metric) for a in distinct[policy].values()]
            known = [v for v in values if type(v) in (int, float) and math.isfinite(v)]
            resources[policy][metric] = {"sum_observed": sum(known) if known else None,
                                         "observed_arms": len(known), "started_arms": len(values),
                                         "complete_total": sum(known) if len(known) == len(values)
                                         and all(a["usage_complete"] for a in distinct[policy].values()) else None}
    return {"schema_version": "pilot-reconciliation-v1", "campaign_id": plan["campaign_id"],
            "configuration": plan["configuration"],
            "scope": "Operational inventory; published comparability is not human validation of evidence/reset",
            "attempts_by_workflow": dict(Counter(r["workflow"] for r in attempts)),
            "planned_pairs": len(trials), "planned_pairs_with_frozen_execution": sum(t["status"] == "executed" for t in trials),
            "frozen_execution_attempts": sum(len(t["frozen_execution_attempts"]) for t in trials),
            "published_comparable_frozen_attempts": sum(len(t["published_comparable_attempts"]) for t in trials),
            "planned_trials": trials, "attempts": attempts, "additional_diagnostic_runs": diagnostics,
            "inspections": sorted(inspections, key=lambda r: r["created_at"]),
            "resources_campaign_and_smoke": resources,
            "limitations": ["No human proof/reset review", "API ZIP excludes hidden files and private evaluation files",
                            "Observed failed attempts and repeated trial IDs are retained separately",
                            "No missing cost is replaced by zero; no new audit was executed"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(reconcile(args.source, load(args.plan)), indent=2) + "\n")


if __name__ == "__main__":
    main()
