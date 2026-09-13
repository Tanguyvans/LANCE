"""Pure diagnostics for unsupported claims in the benchmark funnel.

This module consumes the already-deduplicated findings and the evaluator's
final one-to-one matches.  It does not decide whether evidence is trusted:
only the explicit boolean ``_evidence_supported is True`` is accepted.
"""
from __future__ import annotations

from collections.abc import Callable


_CATEGORIES = (
    "insufficient_evidence",
    "supported_outside_reference",
    "redundant_reference_claim",
    "reference_assignment_conflict",
    "contradicted",
)


def _normalized_strings(value: object) -> list[str]:
    values = value if isinstance(value, (list, tuple, set)) else [value]
    result: list[str] = []
    for item in values:
        if not isinstance(item, str):
            continue
        normalized = item.strip()
        if normalized and normalized not in result:
            result.append(normalized)
    return result


def _evidence_refs(finding: dict) -> list[str]:
    refs: list[str] = []
    for field in ("evidence_ref", "evidence_refs"):
        for ref in _normalized_strings(finding.get(field)):
            if ref not in refs:
                refs.append(ref)
    return refs


def _source_ids(finding: dict) -> list[str]:
    for field in ("source_id", "source_ids", "id", "_candidate_id"):
        values = _normalized_strings(finding.get(field))
        if values:
            return values
    return []


def _claim(finding: dict, category: str, reason: str) -> dict:
    return {
        "id": finding.get("id", ""),
        "device_ip": finding.get("device_ip", ""),
        "service": finding.get("service", ""),
        "port": finding.get("port", ""),
        "type": finding.get("type", ""),
        "evidence_refs": _evidence_refs(finding),
        "category": category,
        "reason": reason,
    }


def build_claim_diagnostics(
    findings: list[dict],
    matches: dict[int, int],
    match: Callable[[list[dict]], dict[int, int]],
) -> dict:
    """Explain every uncredited deduplicated finding without changing counts.

    ``matches`` is the final evaluator association and is treated as the only
    credited reference.  Singleton matching is used only to distinguish a
    supported claim outside the reference set from a redundant claim for a
    ground-truth item already credited elsewhere.  Failed tests and model
    status fields never create a ``contradicted`` diagnostic.
    """
    credited_indices = {
        index for index in matches
        if isinstance(index, int) and 0 <= index < len(findings)
    }
    credited_ground_truth = {
        matches[index] for index in credited_indices
    }
    claims: list[dict] = []
    for index, finding in enumerate(findings):
        if index in credited_indices:
            continue

        trusted = finding.get("_evidence_supported") is True
        if not trusted:
            claims.append(_claim(
                finding,
                "insufficient_evidence",
                "no trusted evidence was recorded for the claim",
            ))
            continue

        singleton_matches = match([finding])
        matched_ground_truth = set(singleton_matches.values())
        if not matched_ground_truth:
            category = "supported_outside_reference"
            reason = "trusted claim has no matching ground-truth reference"
        elif matched_ground_truth & credited_ground_truth:
            category = "redundant_reference_claim"
            reason = "trusted claim matches a ground-truth item already credited"
        else:
            category = "reference_assignment_conflict"
            reason = "trusted claim matches a reference but the final association did not credit it"
        claims.append(_claim(finding, category, reason))

    counts = {category: 0 for category in _CATEGORIES}
    for claim in claims:
        counts[claim["category"]] += 1

    duplicate_sources: list[dict] = []
    for finding in findings:
        members = finding.get("_dedup_members")
        provenance = finding.get("_provenance")
        if isinstance(provenance, dict):
            candidate_ids = _normalized_strings(provenance.get("candidate_ids"))
            if len(candidate_ids) > 1:
                duplicate_sources.append({
                    "source_ids": candidate_ids,
                    "evidence_refs": _evidence_refs(provenance),
                })
        if not isinstance(members, (list, tuple)) or len(members) < 2:
            continue
        source_ids: list[str] = []
        evidence_refs: list[str] = []
        for member in members:
            if not isinstance(member, dict):
                continue
            for source_id in _source_ids(member):
                if source_id not in source_ids:
                    source_ids.append(source_id)
            for ref in _evidence_refs(member):
                if ref not in evidence_refs:
                    evidence_refs.append(ref)
        duplicate_sources.append({
            "source_ids": source_ids,
            "evidence_refs": evidence_refs,
        })

    return {
        "available": True,
        "false_positive_count": len(claims),
        "counts": counts,
        "claims": claims,
        "duplicate_sources": duplicate_sources,
    }
