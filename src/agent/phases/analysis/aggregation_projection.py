"""Pure grouping, provenance and stable canonical identifiers."""
from __future__ import annotations

import logging

from src.agent.finding_identity import finding_identity_key
from src.agent.phases.analysis.mqtt_grouping import group_mqtt_producer_findings

log = logging.getLogger(__name__)


def detect_attack_chains(vulns: list[dict], topology: dict | None) -> list[dict]:
    """Deterministic cross-device attack chain detection.

    Uses graph topology edges + aggregated vuln list to identify multi-hop paths
    where a compromised source device enables access to a downstream target.
    Returns a list of chain_hint dicts injected into 03_vuln_analysis.json so
    Phase 4 and Phase 5 agents can reason about lateral movement paths.
    """
    from src.agent.vuln_taxonomy import is_config_only
    from collections import defaultdict

    by_ip: dict[str, list[dict]] = defaultdict(list)
    for v in vulns:
        by_ip[v.get("device_ip", "")].append(v)

    # Resolve topology edges (scenario mode only for now; lab mode backend TBD)
    if topology is not None:
        edges = topology.get("edges", [])
        node_index = topology["node_index"]
    else:
        return []  # No structured topology available

    _RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    chains: list[dict] = []
    seen: set[tuple[str, str]] = set()

    for e in edges:
        src_node = node_index.get(e.get("source", ""))
        dst_node = node_index.get(e.get("target", ""))
        if not src_node or not dst_node:
            continue

        src_ip = src_node.get("ip", "")
        dst_ip = dst_node.get("ip", "")
        src_vulns = by_ip.get(src_ip, [])
        dst_vulns = by_ip.get(dst_ip, [])

        # Chain: source has exploitable (non-config-only) MEDIUM+ vuln AND dest has any finding
        exploitable_src = [
            v for v in src_vulns
            if _RANK.get((v.get("severity") or "").lower(), 0) >= 2
            and not is_config_only(v.get("type", ""))
        ]

        if exploitable_src and dst_vulns:
            key = (src_ip, dst_ip)
            if key not in seen:
                seen.add(key)
                chains.append({
                    "chain": f"{e['source']} ({src_ip}) -> {e['target']} ({dst_ip})",
                    "src_device": e["source"],
                    "src_ip": src_ip,
                    "dst_device": e["target"],
                    "dst_ip": dst_ip,
                    "pivot_vuln": exploitable_src[0]["id"],
                    "target_vuln_ids": [v["id"] for v in dst_vulns],
                })

    if chains:
        log.info("Detected %d cross-device attack chain(s)", len(chains))
    return chains


def assign_stable_ids(
    final: list[dict], records_by_id: dict, group_identities: dict, previous_ids: dict,
) -> None:
    """Keep phase-2.5 refreshes from reassigning existing verification targets."""
    used_ids: set[str] = set()
    previous_numbers = [
        int(identifier.removeprefix("VULN-"))
        for identifier in previous_ids.values()
        if identifier.removeprefix("VULN-").isdigit()
    ]
    next_number = max(previous_numbers, default=0) + 1

    for finding in final:
        finding_id = previous_ids.get(finding_identity_key(finding))
        if not finding_id:
            finding_id = next((previous_ids[key] for key in group_identities[id(finding)]
                               if key in previous_ids and previous_ids[key] not in used_ids), None)
        if not finding_id or finding_id in used_ids:
            while f"VULN-{next_number:03d}" in used_ids:
                next_number += 1
            finding_id = f"VULN-{next_number:03d}"
            next_number += 1
        used_ids.add(finding_id)
        finding["id"] = finding_id
        finding["canonical_source"] = str(finding.get("_source_kind") or "model")
        for candidate_id in finding["_provenance"]["candidate_ids"]:
            records_by_id[candidate_id]["canonical_finding_id"] = finding_id
        finding.pop("_candidate_id", None)
        finding.pop("_source_kind", None)


def project_candidates(
    eligible: list[dict], records: list[dict], *,
    mqtt_observations: list[dict], previous_ids: dict[tuple, str],
) -> list[dict]:
    """Select canonical representatives while retaining all candidate provenance."""
    records_by_id = {record["candidate_id"]: record for record in records}
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    def finding_quality(finding: dict) -> tuple[int, int, int, int]:
        """Prefer evidence and confirmation; severity is only a final tie-break."""
        confirmed = int(
            (finding.get("exploitation_status") or "").casefold() == "confirmed"
        )
        evidence = str(finding.get("evidence") or "")
        traceability = int(bool(finding.get("evidence_ref") or finding.get("evidence_refs")))
        detail_size = len(evidence) + len(str(finding.get("details") or ""))
        severity = severity_rank.get((finding.get("severity") or "").casefold(), 0)
        return confirmed, traceability, detail_size, severity

    deduped: list[dict] = []
    group_identities: dict[int, list[tuple]] = {}
    for candidates, producer_normalized in group_mqtt_producer_findings(
        eligible, observations=mqtt_observations,
    ):
        chosen = max(candidates, key=finding_quality)
        group_identities[id(chosen)] = [finding_identity_key(item) for item in candidates]
        # A unique compatible anchor supplies only actually recorded
        # product/version metadata, never invented combinations.
        for field in ("product", "version"):
            if not chosen.get(field):
                chosen[field] = next((item[field] for item in candidates if item.get(field)), "")
        candidate_ids = [item["_candidate_id"] for item in candidates]
        evidence_refs: list[str] = []
        candidate_evidence_refs: dict[str, list[str]] = {}
        for candidate in candidates:
            candidate_refs: list[str] = []
            for field in ("evidence_ref", "evidence_refs"):
                values = candidate.get(field)
                if not isinstance(values, (list, tuple, set)):
                    values = [values]
                for value in values:
                    ref = str(value or "").strip()
                    if ref and ref not in candidate_refs:
                        candidate_refs.append(ref)
                    if ref and ref not in evidence_refs:
                        evidence_refs.append(ref)
            candidate_evidence_refs[candidate["_candidate_id"]] = candidate_refs
        chosen_evidence_refs = candidate_evidence_refs.get(chosen["_candidate_id"], [])
        chosen["_provenance"] = {
            "selected_candidate_id": chosen["_candidate_id"],
            "candidate_ids": candidate_ids,
            "candidate_sources": {
                item["_candidate_id"]: {
                    "source_file": records_by_id[item["_candidate_id"]].get("source_file", ""),
                    "source_kind": records_by_id[item["_candidate_id"]].get("source_kind", ""),
                    "source_index": records_by_id[item["_candidate_id"]].get("source_index"),
                }
                for item in candidates
            },
            "source_files": sorted({
                records_by_id[item["_candidate_id"]].get("source_file", "")
                for item in candidates
                if records_by_id[item["_candidate_id"]].get("source_file", "")
            }),
            # Producer-backed grouping never promotes another member's
            # proof onto the selected finding.  The complete per-candidate
            # ref map remains auditable here and in the raw registry.
            "evidence_refs": chosen_evidence_refs if producer_normalized else evidence_refs,
            "candidate_evidence_refs": candidate_evidence_refs,
            "raw_projection": "03_vuln_analysis_raw.json",
            "grouping_basis": (
                "archived_phase3_mqtt_observation"
                if producer_normalized else "conservative_finding_identity"
            ),
        }
        if evidence_refs and not producer_normalized:
            chosen["evidence_refs"] = evidence_refs
        deduped.append(chosen)
        for item in candidates:
            record = records_by_id[item["_candidate_id"]]
            if item is chosen:
                record["accepted_for_canonical"] = True
                record["decision"] = "selected"
                record["decision_reason"] = (
                    "best evidence/confirmation quality in canonical duplicate group"
                )
            else:
                record["decision"] = "deduplicated"
                record["decision_reason"] = (
                    f"represented by {chosen['_candidate_id']}; raw candidate preserved"
                )

    assign_stable_ids(deduped, records_by_id, group_identities, previous_ids)
    return deduped
