"""Normalize candidate copies, assess CVEs and record explicit exclusions."""
from __future__ import annotations

from copy import deepcopy
import logging
import re

from src.agent.finding_policy import finding_semantic_issue, normalise_full_finding_semantics
from src.agent.vuln_taxonomy import canonicalize, is_noise
from src.benchmark.strict_v3 import cve_is_allowed
from src.agent.phases.analysis.aggregation_context import AggregationContext, AggregationInputs
from src.agent.phases.analysis.compact import apply_compact_finding_policy
from src.agent.phases.analysis.evidence import _enrich_finding_structure, _sanitize_suggested_tools

log = logging.getLogger(__name__)


def validate_cve_claim(finding: dict, cve_search_evidence: dict, *, benchmark_split: str) -> None:
    """Annotate scoring compatibility; unknown compatibility remains schedulable."""
    validation = finding.get("cve_validation")
    validation = validation if isinstance(validation, dict) else {}
    query = str(validation.get("query", "")).strip().casefold()
    claimed_ids = [
        str(cve_id).upper()
        for cve_id in finding.get("cve_ids", [])
        if re.fullmatch(r"CVE-\d{4}-\d{4,}", str(cve_id).upper())
    ]
    assessments = {
        cve_id: cve_search_evidence.get((query, cve_id))
        for cve_id in claimed_ids
    }
    compatible_ids = [
        cve_id for cve_id, assessment in assessments.items()
        if assessment and assessment.get("status") == "compatible"
    ]
    observed_statuses = {
        assessment.get("status")
        for assessment in assessments.values()
        if assessment
    }
    catalog_compatible_ids = []
    validation_product = str(validation.get("observed_product") or finding.get("product") or "")
    validation_version = str(validation.get("observed_version") or finding.get("version") or "")
    if not claimed_ids:
        finding["_cve_structural_issue"] = (
            "CVE claim lacks a valid CVE identifier"
        )
    product_text = validation_product.casefold()
    if "dropbear" in product_text:
        product_tokens = ["dropbear"]
        # The strict contract uses the product family, while
        # scanners commonly return "Dropbear sshd". Normalize
        # only the canonical CVE projection; raw evidence keeps
        # the full observed product string.
        finding["product"] = "Dropbear"
    elif "openssh" in product_text:
        product_tokens = ["openssh"]
    elif re.search(r"\bssh\b", product_text):
        product_tokens = ["ssh"]
    else:
        product_tokens = []
    finding_text = " ".join(
        str(finding.get(key) or "")
        for key in ("details", "evidence")
    )
    for claimed_id in claimed_ids:
        if (
            re.search(rf"(?i)\b{re.escape(claimed_id)}\b", finding_text)
            and product_tokens
            and validation_version
            and any(
                cve_is_allowed(claimed_id, [product], [validation_version])
                for product in product_tokens
            )
        ):
            catalog_compatible_ids.append(claimed_id)
    if (
        compatible_ids
        and len(compatible_ids) < len(claimed_ids)
    ):
        claim_status = "partially_validated"
        finding["accepted_for_scoring"] = False
    elif (
        compatible_ids
        and not catalog_compatible_ids
        and benchmark_split != "unassigned"
    ):
        # strict-v3 is released with a reviewed offline CVE
        # catalogue. A live/NVD-compatible claim outside that
        # catalogue remains an auditable candidate, but is not
        # promoted into the scored queue.
        claim_status = "unreviewed_catalog"
        finding["accepted_for_scoring"] = False
    elif compatible_ids:
        claim_status = "validated"
        finding["cve_ids"] = claimed_ids
        finding["accepted_for_scoring"] = True
    elif catalog_compatible_ids and len(catalog_compatible_ids) < len(claimed_ids):
        claim_status = "partially_validated_catalog"
        finding["accepted_for_scoring"] = False
    elif catalog_compatible_ids:
        # The archived search can be indeterminate when NVD has no
        # CPE range for a cross-vendor CVE such as Terrapin. The
        # reviewed offline catalogue remains authoritative when
        # the model supplied explicit CVE, product, version, and
        # evidence context. This preserves recall without
        # accepting free-form or future CVE claims.
        claim_status = "validated_catalog"
        finding["cve_ids"] = claimed_ids
        finding["accepted_for_scoring"] = True
    elif "conditional" in observed_statuses:
        claim_status = "conditional"
        finding["accepted_for_scoring"] = False
    elif "indeterminate" in observed_statuses:
        claim_status = "uncertain"
        finding["accepted_for_scoring"] = False
    elif (
        claimed_ids
        and all(assessment is not None for assessment in assessments.values())
        and observed_statuses == {"incompatible"}
    ):
        claim_status = "incompatible"
        finding["accepted_for_scoring"] = False
    else:
        claim_status = "unverified"
        finding["accepted_for_scoring"] = False
    finding["cve_claim_status"] = claim_status
    finding["cve_tool_evidence"] = {
        cve_id: assessment
        for cve_id, assessment in assessments.items()
        if assessment
    }


def normalize_candidates(context: AggregationContext, inputs: AggregationInputs) -> list[dict]:
    all_vulns = inputs.findings
    records_by_id = {record["candidate_id"]: record for record in inputs.records}
    compact_mode = context.compact_local
    surface_roles = context.surface_roles
    cve_search_evidence = inputs.cve_evidence
    catalog_tool_names = context.tool_names
    # Freeze the pre-filter identity. Later semantic normalization is an
    # operation to evaluate, not a reason to rewrite the candidate snapshot.
    for finding in all_vulns:
        candidate = deepcopy({key: value for key, value in finding.items() if not key.startswith("_")})
        candidate["type"] = canonicalize(candidate.get("type", ""))
        _enrich_finding_structure(candidate, strict_schema=not compact_mode)
        records_by_id[finding["_candidate_id"]]["candidate_finding"] = candidate
    if not compact_mode:
        # Normalize all candidates before semantic checks so related claims
        # (for example /api/devices and /api/status) can be reasoned about
        # together. Raw candidates remain untouched in the audit registry.
        for finding in all_vulns:
            finding["type"] = canonicalize(finding.get("type", ""))
            _enrich_finding_structure(finding, strict_schema=True)
            port = finding.get("port")
            if isinstance(port, str) and port.isdigit():
                finding["port"] = int(port)
        for finding in all_vulns:
            normalise_full_finding_semantics(
                finding,
                all_vulns,
                device_role=surface_roles.get(
                    str(finding.get("device_id") or ""), ""
                ),
            )

    for finding in all_vulns:
        _sanitize_suggested_tools(finding, catalog_names=catalog_tool_names)
        finding["type"] = canonicalize(finding.get("type", ""))
        if compact_mode:
            _enrich_finding_structure(finding)
            apply_compact_finding_policy(finding)
        else:
            _enrich_finding_structure(finding, strict_schema=True)
        port = finding.get("port")
        if isinstance(port, str) and port.isdigit():
            finding["port"] = int(port)
        if finding.get("type") == "known_cve":
            validate_cve_claim(finding, cve_search_evidence, benchmark_split=context.benchmark_split)
        record = records_by_id[finding["_candidate_id"]]
        source_kind = str(finding.get("_source_kind") or record.get("source_kind") or "")
        device_id = str(finding.get("device_id") or "")
        device_role = surface_roles.get(device_id, "")
        if not str(finding.get("device_ip") or finding.get("device_id") or "").strip():
            record["decision"] = "excluded_from_canonical"
            record["decision_reason"] = "finding lacks a target device and is not testable"
            continue
        semantic_issue = finding_semantic_issue(
            finding,
            source_kind=source_kind,
            compact=compact_mode,
            device_role=device_role,
            context_findings=all_vulns,
        )
        if semantic_issue:
            record["decision"] = "excluded_from_canonical"
            record["decision_reason"] = semantic_issue
            continue
        record["normalized"] = {
            key: finding.get(key)
            for key in (
                "device_id", "device_ip", "type", "severity", "service",
                "port", "protocol", "endpoint", "endpoints", "product", "version",
            )
        }

    # Preserve the historical dict-only remapping contract for list surfaces.
    try:
        for finding in all_vulns:
            if finding.get("device_id", "").startswith("discovered-"):
                canonical = context.ip_to_device_id.get(finding.get("device_ip", ""))
                if canonical:
                    finding["device_id"] = canonical
    except Exception as exc:
        log.debug("device_id remap skipped: %s", exc)

    eligible: list[dict] = []
    for finding in all_vulns:
        record = records_by_id[finding["_candidate_id"]]
        if record.get("decision") == "excluded_from_canonical":
            continue
        vuln_type = finding.get("type", "")
        if is_noise(vuln_type):
            record["decision"] = "excluded_from_canonical"
            record["decision_reason"] = "taxonomy marks this as a non-finding/noise type"
            continue
        if vuln_type == "known_cve" and finding.get("_cve_structural_issue"):
            record["decision"] = "excluded_from_canonical"
            record["decision_reason"] = finding["_cve_structural_issue"]
            continue
        # Compatibility is a scoring attribute, not an admission gate:
        # an unverified but well-formed CVE remains schedulable for Phase
        # 4, while a claim proven incompatible is excluded explicitly.
        if vuln_type == "known_cve" and finding.get("cve_claim_status") == "incompatible":
            record["decision"] = "excluded_from_canonical"
            record["decision_reason"] = (
                "CVE claim is explicitly incompatible according to the archived cve_search result"
            )
            continue
        eligible.append(finding)

    return eligible
