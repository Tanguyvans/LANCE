"""Read-only paired D1/A1 evaluation. Never runs tools or deploys a laboratory."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from dataclasses import asdict
from pathlib import Path

from src.agent.audit_experiment import digest, load_inventory
from src.benchmark.comparability import configuration_identity
from src.benchmark.evaluator import evaluate


# Policy and provider/model are the intentional treatment differences. All
# other configuration fields, including rules shared by both arms, must match.
TREATMENT_FIELDS = {"decision_policy", "provider", "model"}
PAIR_FIELDS = (
    "experiment", "inventory_sha256", "runtime_unavailable_tools",
    "cve_lookup_policy", "cve_source", "episodic_memory_enabled",
)
METRICS = (
    "total_cost_usd", "total_tokens", "total_turns", "total_tool_calls",
    "total_tool_errors", "wall_clock_duration_s", "specificity",
    "negative_control_specificity", "negative_control_violations",
)


def _number(value):
    return value if not isinstance(value, bool) and isinstance(value, (int, float)) and math.isfinite(value) else None


def _arm(path: Path | None, policy: str, truth: Path) -> tuple[dict, dict | None, list[str]]:
    arm = {"run_dir": str(path) if path else None, "status": "missing", "evaluation": None, "metrics": {}}
    problems = []
    if path is None or not path.is_dir():
        return arm, None, [f"{policy}: missing run"]
    try:
        meta = json.loads((path / "run_meta.json").read_text(encoding="utf-8"))
        if not isinstance(meta, dict):
            raise ValueError("metadata must be an object")
        arm["status"] = meta.get("status", "unknown")
        identity, reason = configuration_identity(meta, scoring_policy="strict-v3")
        if reason:
            problems.append(f"{policy}: {reason}")
        if meta.get("policy_schema_version") != 1 or meta.get("decision_policy") != policy:
            problems.append(f"{policy}: wrong or missing policy schema/arm")
        inventory = load_inventory(path / "audit_inventory.json")
        if meta.get("inventory_sha256") != digest(inventory) or meta.get("experiment") != inventory["experiment"]:
            problems.append(f"{policy}: inventory hash or experiment mismatch")
        if meta.get("cve_lookup_policy") != "cache_only" or meta.get("episodic_memory_enabled") is not False:
            problems.append(f"{policy}: mutable knowledge configuration")
        if meta.get("status") != "completed" or meta.get("evidence_integrity") is not True or meta.get("usage_status") != "completed":
            problems.append(f"{policy}: incomplete run, evidence or usage")
        result = evaluate(path, truth)
        arm["evaluation"] = asdict(result)
        if not result.evidence_contract_compatible or not result.process_metrics_available or result.process_metrics_schema_version != 3:
            problems.append(f"{policy}: incompatible evidence/process metrics")
        stages = result.funnel.get("stages", {})
        if any(not stages.get(stage, {}).get("available") for stage in ("candidates", "filtered", "confirmed")):
            problems.append(f"{policy}: missing evaluable stage artifacts")
        if result.phase3_status != "completed":
            problems.append(f"{policy}: incomplete analysis")
        cost = json.loads((path / "cost_summary.json").read_text(encoding="utf-8"))
        metrics = {name: _number(getattr(result, name, None)) for name in METRICS}
        metrics["wall_clock_duration_s"] = _number(cost.get("wall_clock_duration_s"))
        if policy == "rules" and any(metrics.get(key) != 0 for key in ("total_cost_usd", "total_tokens", "total_turns")):
            problems.append("rules: unexpected model consumption")
        for stage in ("candidates", "filtered", "confirmed"):
            for metric in ("true_positives", "false_positives", "false_negatives", "precision", "recall", "f1", "invalid_evidence"):
                metrics[f"{stage}.{metric}"] = _number(stages.get(stage, {}).get(metric))
        tp = metrics.get("confirmed.true_positives")
        metrics["llm_cost_per_confirmed_tp"] = metrics["total_cost_usd"] / tp if tp and metrics["total_cost_usd"] is not None else None
        arm["metrics"] = metrics
        arm["undefined_metrics"] = [key for key, value in metrics.items() if value is None]
        if identity is not None:
            for key in PAIR_FIELDS:
                if key not in meta:
                    problems.append(f"{policy}: missing pairing field {key}")
            identity = {**identity, **{key: meta.get(key) for key in PAIR_FIELDS}}
        return arm, identity, problems
    except (OSError, ValueError, TypeError, KeyError) as exc:
        return arm, None, [*problems, f"{policy}: {type(exc).__name__}: {exc}"]


def compare_runs(rules_run: Path | None, llm_run: Path | None, ground_truth: Path) -> dict:
    """Report both arms and missing data; only emit deltas for a valid pair."""
    rules, rules_id, problems = _arm(rules_run, "rules", ground_truth)
    llm, llm_id, llm_problems = _arm(llm_run, "llm", ground_truth)
    problems.extend(llm_problems)
    if rules_id is not None and llm_id is not None:
        for key in sorted((set(rules_id) | set(llm_id)) - TREATMENT_FIELDS):
            if rules_id.get(key) != llm_id.get(key):
                problems.append(f"pair: incompatible {key}")
    comparable = not problems and rules_id is not None and llm_id is not None
    delta = None
    if comparable:
        delta = {
            key: llm["metrics"][key] - value if value is not None and llm["metrics"].get(key) is not None else None
            for key, value in rules["metrics"].items()
        }
    return {
        "schema_version": "policy-pair-v1", "comparable": comparable,
        "incomparability_reasons": problems, "arms": {"rules": rules, "llm": llm},
        "delta_llm_minus_rules": delta,
        "ground_truth_sha256": hashlib.sha256(ground_truth.read_bytes()).hexdigest(),
        "uncertainty": {"available": False, "reason": "One declared pair; no family-level confidence interval or generalization claim"},
        "cost_scope": "LLM usage only; infrastructure, development and human review costs are not measured",
        "environment_scope": "Initial environment fingerprint is operator-declared; equality does not attest a laboratory reset",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules-run", type=Path)
    parser.add_argument("--llm-run", type=Path)
    parser.add_argument("--ground-truth", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.rules_run is None and args.llm_run is None:
        parser.error("Supply at least one run; an absent arm is reported as missing")
    try:
        result = compare_runs(args.rules_run, args.llm_run, args.ground_truth)
        content = json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
        if args.output:
            args.output.write_text(content, encoding="utf-8")
        else:
            print(content, end="")
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    return 0 if result["comparable"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
