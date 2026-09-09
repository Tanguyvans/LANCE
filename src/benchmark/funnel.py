"""Stage-local accounting: candidates, filtered predictions, final reports.

Ground-truth matching and proof validation are supplied by the evaluator, never
by the agent. A failed attempt is not negative evidence about a vulnerability.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Callable

from src.agent.vuln_taxonomy import NOISE_TYPES, canonicalize
from src.agent.report_evidence import verification_state


STAGES = ("candidates", "filtered", "confirmed")


def _read(path: Path, key: str) -> list | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        value = payload.get(key)
        return value if isinstance(value, list) else None
    except (OSError, ValueError, AttributeError):
        return None


def unique_predictions(findings: list[dict]) -> list[dict]:
    """Collapse exact structural duplicates, not different targets/endpoints.

    Model-authored IDs are not identities. Missing structure is not a wildcard:
    a vague claim cannot silently absorb a distinct, precise prediction.
    """
    result: dict[str, dict] = {}
    for finding in findings:
        item = dict(finding)
        item["type"] = canonicalize(str(item.get("type") or ""))
        if item["type"] in NOISE_TYPES:
            continue
        identity = {key: str(item.get(key) or "").strip() for key in (
            "device_ip", "type", "service", "port", "protocol", "endpoint", "product", "version",
        )}
        for key in ("device_ip", "type", "service", "protocol", "product"):
            identity[key] = identity[key].casefold()
        for key in ("endpoints", "cve_ids"):
            values = item.get(key) or []
            if isinstance(values, str):
                values = [values]
            identity[key] = sorted(set(
                str(v).casefold() if key == "cve_ids" else str(v) for v in values
            ))
        # Unidentifiable predictions remain separate audit errors, not one
        # magically deduplicated claim shared across unrelated devices.
        if not identity["device_ip"] or not identity["type"]:
            identity["unidentified_index"] = len(result)
        signature = json.dumps(identity, sort_keys=True)
        if signature not in result:
            result[signature] = item
        else:
            existing = result[signature]
            if item.get("_evidence_supported") and not existing.get("_evidence_supported"):
                result[signature] = item
    return list(result.values())


def stage_metrics(
    findings: list[dict], gt_count: int, matched: dict[int, int],
    *, supported: set[int] | None = None,
) -> dict:
    """Count predictions once; proof-invalid confirmations are not valid TPs."""
    valid = {index: gt for index, gt in matched.items() if supported is None or index in supported}
    pred, tp = len(findings), len(valid)
    fp, fn = pred - tp, gt_count - tp
    precision = tp / pred if pred else None
    recall = tp / gt_count if gt_count else None
    f1 = 2 * tp / (pred + gt_count) if gt_count else None
    return {
        "available": True, "predictions": pred,
        "true_positives": tp, "false_positives": fp, "false_negatives": fn,
        "precision": round(precision, 3) if precision is not None else None,
        "recall": round(recall, 3) if recall is not None else None,
        "f1": round(f1, 3) if f1 is not None else None,
        "ground_truth_matches": len(matched),
        "invalid_evidence": pred - len(supported) if supported is not None else 0,
        "matched_gt_indices": sorted(valid.values()),
    }


def unavailable_stage(reason: str) -> dict:
    return {"available": False, "reason": reason, **{key: None for key in (
        "predictions", "true_positives", "false_positives", "false_negatives",
        "precision", "recall", "f1", "ground_truth_matches", "invalid_evidence",
    )}}


def evaluate_funnel(
    run_dir: Path, *, gt_count: int, filtered: list[dict], confirmations: list[dict],
    match: Callable[[list[dict]], dict[int, int]],
    validate: Callable[[list[dict]], set[int]],
    compatible: bool, provenance_available: bool,
    compatibility_reason: str | None = None, total_cost: float | None = None,
    total_turns: int | None = None,
) -> dict:
    """Evaluate independent snapshots. Never reconstruct candidates from survivors."""
    raw = _read(run_dir / "03_vuln_analysis_raw.json", "candidates")
    p3 = _read(run_dir / "03_vuln_analysis.json", "vulnerabilities")
    tests = _read(run_dir / "04_exploitation.json", "tests")
    result = {"schema_version": "funnel-v1", "stages": {}, "diagnostics": {}}
    stages, diagnostics = result["stages"], result["diagnostics"]
    # Validate before deduplication so a proof belonging to the second copy of
    # the same finding is not lost (and vague copies cannot steal tool refs).
    supported_confirmations = validate(confirmations) if compatible and provenance_available else set()
    confirmations = [{**f, "_evidence_supported": i in supported_confirmations} for i, f in enumerate(confirmations)]
    snapshots = {"filtered": unique_predictions(filtered), "confirmed": unique_predictions(confirmations)}
    if raw is not None:
        candidates = []
        decisions = Counter()
        malformed = 0
        for record in raw:
            if not isinstance(record, dict):
                malformed += 1
                continue
            decisions[str(record.get("decision") or "unknown")] += 1
            candidate = record.get("candidate_finding", record.get("raw_finding"))
            if not isinstance(candidate, dict):
                malformed += 1
                continue
            candidates.append(candidate)
        snapshots["candidates"] = unique_predictions(candidates)
        observations = sum(canonicalize(str(f.get("type") or "")) in NOISE_TYPES for f in candidates)
        diagnostics.update(
            raw_records=len(raw), malformed_candidates=malformed,
            non_vulnerability_observations=observations,
            duplicate_candidates=len(candidates) - observations - len(snapshots["candidates"]),
            filter_decisions=dict(decisions),
        )

    for name in STAGES:
        reason = None
        if not compatible:
            reason = compatibility_reason or "Incompatible metric contract"
        elif name == "candidates" and raw is None:
            reason = "Missing or invalid candidate registry; cannot reconstruct pre-filter predictions"
        elif p3 is None:
            reason = "Missing or invalid Phase 3 artifact"
        elif name == "confirmed" and tests is None:
            reason = "Missing or invalid Phase 4 artifact"
        elif name == "confirmed" and not provenance_available:
            reason = "Missing or invalid tool provenance log"
        if reason:
            stages[name] = unavailable_stage(reason)
            continue
        findings = snapshots[name]
        supported = {i for i, f in enumerate(findings) if f.get("_evidence_supported")} if name == "confirmed" else None
        # Match supported claims first: an unsupported duplicate/alternative
        # cannot steal a GT entry from a genuinely proven confirmation.
        matching_input = findings if supported is None else [
            f for i, f in enumerate(findings) if i in supported
        ]
        if supported is None:
            matches = match(matching_input)
        else:
            indices = sorted(supported)
            matches = {indices[i]: gt for i, gt in match(matching_input).items()}
        stages[name] = stage_metrics(findings, gt_count, matches, supported=supported)
        if supported is not None:
            stages[name]["ground_truth_matches"] = len(match(findings))

    # One verification state per canonical candidate. Duplicate or orphan test
    # IDs cannot inflate coverage, and conflicting results remain indeterminate.
    if compatible and p3 is not None and tests is not None:
        by_id: dict[str, list[dict]] = {}
        for test in tests:
            if isinstance(test, dict):
                by_id.setdefault(str(test.get("vuln_id") or test.get("id") or ""), []).append(test)
        counts = Counter({"confirmed": 0, "refuted": 0, "inconclusive": 0, "error": 0, "not_tested": 0})
        ids = Counter(str(f.get("id") or "") for f in snapshots["filtered"])
        for finding in snapshots["filtered"]:
            identifier = str(finding.get("id") or "")
            entries = by_id.get(identifier, [])
            if not entries:
                state = "not_tested"
            elif not identifier or ids[identifier] != 1 or len(entries) != 1:
                state = "inconclusive"
            else:
                state = verification_state(entries[0])
            counts[state] += 1
        n = len(snapshots["filtered"])
        diagnostics["verification"] = dict(counts)
        diagnostics["verification_attempt_rate"] = round((n - counts["not_tested"]) / n, 3) if n else None
        diagnostics["orphan_tests"] = sum(len(v) for k, v in by_id.items() if k not in ids)
        diagnostics["unsupported_declarations"] = sum(
            str(t.get("status") or "").upper() == "CONFIRMED" and verification_state(t) != "confirmed"
            for t in tests if isinstance(t, dict)
        )

    candidate, retained, final = (stages[name] for name in STAGES)
    diagnostics["proofs"] = {"available": final["available"], **{
        state: sum(f.get("_proof_status") == state for f in snapshots["confirmed"])
        if final["available"] else None
        for state in ("accepted", "rejected", "missing")
    }}
    if candidate["available"] and retained["available"]:
        initial = set(candidate["matched_gt_indices"])
        after = set(retained["matched_gt_indices"])
        diagnostics["true_candidates_lost_in_filter"] = len(initial - after)
        diagnostics["new_gt_matches_after_normalization"] = len(after - initial)
        diagnostics["false_predictions_removed_by_filter"] = candidate["false_positives"] - retained["false_positives"]
    if retained["available"] and final["available"]:
        before = set(retained["matched_gt_indices"])
        after = set(final["matched_gt_indices"])
        diagnostics["true_candidates_not_confirmed"] = len(before - after)
        diagnostics["true_candidate_confirmation_rate"] = round(len(before & after) / len(before), 3) if before else None
        diagnostics["cost_per_valid_confirmation"] = (
            round(total_cost / final["true_positives"], 6)
            if total_cost is not None and final["true_positives"] else None
        )
        diagnostics["turns_per_valid_confirmation"] = (
            round(total_turns / final["true_positives"], 3)
            if total_turns is not None and final["true_positives"] else None
        )
    return result
