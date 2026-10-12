"""Structural admission of model candidates before semantic normalization.

Missing fields remain hypotheses to assess; malformed present fields must not
reach code that expects scalars, arrays or mappings. This check does not certify
the finding, its evidence or its CVE compatibility.
"""
from __future__ import annotations


def finding_structure_issue(finding: object) -> str | None:
    if not isinstance(finding, dict):
        return "finding must be an object"
    for field in (
        "id", "device_id", "device_ip", "type", "severity", "service",
        "protocol", "endpoint", "product", "version", "details", "evidence",
        "exploitation_status", "status", "evidence_ref", "device_role", "role",
        "condition", "parameter", "vector", "claim", "suggested_technique",
    ):
        if finding.get(field) is not None and not isinstance(finding[field], str):
            return f"{field} must be a string or null"
    for field in ("cve_ids", "endpoints", "evidence_refs", "suggested_tools"):
        if field not in finding:
            continue
        value = finding[field]
        if field != "cve_ids" and value is None:
            continue
        if field in {"suggested_tools", "evidence_refs"} and isinstance(value, str):
            continue
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            return f"{field} must be an array of strings"
    if finding.get("cve_validation") is not None and not isinstance(finding["cve_validation"], dict):
        return "cve_validation must be an object or null"
    port = finding.get("port")
    if port not in (None, ""):
        if isinstance(port, bool) or not isinstance(port, (str, int)):
            return "port must be an integer in 1..65535 or null"
        if isinstance(port, str) and not port.isdecimal():
            return "port must be an integer in 1..65535 or null"
        try:
            number = int(port)
        except ValueError:
            return "port must be an integer in 1..65535 or null"
        if not 0 < number <= 65535:
            return "port must be an integer in 1..65535 or null"
    return None
