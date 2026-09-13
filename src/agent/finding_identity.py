"""Pure identity for canonical findings and funnel accounting.

Finding IDs and evidence references are provenance, not prediction identity.
This intentionally keeps condition/detail spelling because two hypotheses on
the same surface are not equivalent without an explicit structured proof.
"""
from __future__ import annotations

import re

from src.agent.exploit_evidence import extract_endpoint_paths


def _values(value: object) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value or "").strip()
    return [text] if text else []


def finding_identity_key(finding: dict) -> tuple:
    """Return a conservative, provenance-independent finding identity."""
    service = str(finding.get("service") or "").strip().casefold()
    protocol = str(finding.get("protocol") or "").strip().casefold()
    try:
        port = int(finding.get("port"))
    except (TypeError, ValueError):
        port = str(finding.get("port") or "").strip()

    endpoint_values = _values(finding.get("endpoint")) + _values(finding.get("endpoints"))
    # mqtt-ws no-auth plans historically spell their implicit root endpoint
    # either as ``/`` or as empty.  This is the sole non-HTTP default we
    # collapse; HTTP and every other protocol keep endpoint identity exact.
    finding_type = str(finding.get("type") or "").strip().casefold()
    if (service in {"mqtt-ws", "mqtt_websocket", "mqtt-websocket"}
            and finding_type == "no_auth"
            and set(endpoint_values) == {"/"}):
        endpoint_values = []
    if not endpoint_values and service in {"http", "https"}:
        endpoint_values = extract_endpoint_paths(finding.get("details"), finding.get("evidence"))
    endpoint_key = tuple(sorted(set(endpoint_values)))

    conditions = []
    for field in ("condition", "parameter", "vector", "claim"):
        value = str(finding.get(field) or "").strip()
        if value:
            conditions.append((field, re.sub(r"\s+", " ", value)))
    details = str(finding.get("details") or "").strip()
    if details:
        conditions.append(("details", re.sub(r"\s+", " ", details)))
    elif not conditions:
        evidence = str(finding.get("evidence") or "").strip()
        if evidence:
            conditions.append(("evidence", re.sub(r"\s+", " ", evidence)))

    cves = tuple(sorted(value.casefold() for value in _values(finding.get("cve_ids"))))
    target = str(finding.get("device_ip") or finding.get("device_id") or "").strip()
    return (
        target,
        str(finding.get("type") or "").strip().casefold(),
        service,
        port,
        protocol,
        endpoint_key,
        str(finding.get("product") or "").strip().casefold(),
        str(finding.get("version") or "").strip().casefold(),
        cves,
        tuple(conditions),
    )


def _finding_sort_key(finding: dict) -> str:
    """Return a stable ordering key without changing the finding object."""
    return repr(sorted(finding.items(), key=lambda item: str(item[0])))


def _metadata_dominates(small: tuple[str, str], large: tuple[str, str]) -> bool:
    """Whether ``large`` is a strictly more-specific compatible tuple."""
    if small == large:
        return False
    return all(not value or value == large[index] for index, value in enumerate(small))


def group_equivalent_findings(findings: list[dict]) -> list[list[dict]]:
    """Group findings equivalent under conservative metadata completion.

    The base identity is the exact ``finding_identity_key`` with only its
    product/version positions removed.  Within each base partition, metadata
    buckets are joined to a unique compatible maximal bucket.  An incomplete
    bucket compatible with multiple maxima remains separate, preventing it
    from bridging conflicting product/version observations.  Findings missing
    a target or type are deliberately never deduplicated.
    """
    partitions: dict[tuple, list[dict]] = {}
    unidentifiable: list[dict] = []
    for finding in findings:
        key = finding_identity_key(finding)
        if not key[0] or not key[1]:
            unidentifiable.append(finding)
            continue
        base = key[:6] + key[8:]
        partitions.setdefault(base, []).append(finding)

    groups: list[list[dict]] = [[finding] for finding in unidentifiable]
    for base, partition in partitions.items():
        buckets: dict[tuple[str, str], list[dict]] = {}
        for finding in partition:
            key = finding_identity_key(finding)
            metadata = (key[6], key[7])
            buckets.setdefault(metadata, []).append(finding)

        bucket_keys = sorted(buckets)
        maxima = [
            candidate for candidate in bucket_keys
            if not any(
                _metadata_dominates(candidate, other)
                for other in bucket_keys
            )
        ]
        assignments: dict[tuple[str, str], tuple[str, str]] = {}
        for bucket in bucket_keys:
            compatible_maxima = [
                maximum for maximum in maxima
                if _metadata_dominates(bucket, maximum) or bucket == maximum
            ]
            if len(compatible_maxima) == 1:
                assignments[bucket] = compatible_maxima[0]

        grouped: dict[tuple[str, str], list[dict]] = {}
        for bucket in bucket_keys:
            destination = assignments.get(bucket, bucket)
            grouped.setdefault(destination, []).extend(
                sorted(buckets[bucket], key=_finding_sort_key)
            )
        groups.extend(
            sorted(
                grouped.values(),
                key=lambda group: (repr(base), _finding_sort_key(group[0])),
            )
        )

    return sorted(
        groups,
        key=lambda group: (
            repr(finding_identity_key(group[0])[:6] + finding_identity_key(group[0])[8:]),
            _finding_sort_key(group[0]),
        ),
    )
