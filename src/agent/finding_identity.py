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
