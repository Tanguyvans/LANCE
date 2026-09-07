"""Normalize finding structure and tool suggestions without inventing observations."""
from __future__ import annotations
import re
from urllib.parse import urlsplit
from src.benchmark.tool_registry import available_tool_names
from src.agent.exploit_evidence import extract_endpoint_paths as _extract_endpoint_paths


def _sanitize_suggested_tools(
    finding: dict,
    *,
    catalog_names: set[str] | None = None,
) -> list[str]:
    """Keep model-provided tool suggestions inside the repository catalog.

    Models often emit a CLI, package, or command-line recipe in
    ``suggested_tools`` (for example ``ffplay`` or ``nmap ssh-vulnscan``).
    Those are not callable provider functions and can steer a later phase
    toward an unavailable tool.  The raw candidate remains in the audit
    registry; the canonical finding receives only exact catalog names.  A
    hyphen is accepted solely as the display spelling of an underscored
    catalog name, such as ``ssh-audit`` -> ``ssh_audit``.
    """
    if "suggested_tools" not in finding:
        return []

    allowed = set(available_tool_names() if catalog_names is None else catalog_names)
    raw = finding.get("suggested_tools")
    if isinstance(raw, str):
        values = [raw]
    elif isinstance(raw, (list, tuple, set)):
        values = list(raw)
    else:
        values = []

    cleaned: list[str] = []
    for value in values:
        if not isinstance(value, (str, int, float)):
            continue
        value = str(value).replace("\n", ",")
        for item in re.split(r"[,;|\\n]+", str(value)):
            token = item.strip().strip("`'\"")
            if not token:
                continue
            canonical = token.casefold().replace("-", "_")
            if canonical in allowed and re.fullmatch(r"[a-z0-9_]+", canonical):
                if canonical not in cleaned:
                    cleaned.append(canonical)

    finding["suggested_tools"] = cleaned
    return cleaned


def _enrich_finding_structure(
    finding: dict,
    *,
    strict_schema: bool = False,
) -> dict:
    """Fill deterministic strict-v3 structure without inventing observations.

    The full profile emits the canonical strict-v3 queue, so nullable scalar
    fields from a model response are normalized to schema-neutral empty values
    before validation. Compact keeps its existing projection behavior; its
    caller deliberately leaves ``strict_schema`` disabled.
    """
    if strict_schema:
        for field in ("service", "protocol", "product", "version"):
            if finding.get(field) is None:
                finding[field] = ""
        if finding.get("endpoint") is None:
            finding["endpoint"] = ""

    service = str(finding.get("service", "")).strip().casefold()
    if service and not str(finding.get("protocol", "")).strip():
        finding["protocol"] = "udp" if service in {"coap", "snmp", "bacnet"} else "tcp"
    elif str(finding.get("protocol", "")).strip().casefold() not in {"", "tcp", "udp"}:
        # protocol is the transport protocol in the strict queue. Models
        # sometimes copy the application protocol (for example http), which
        # made an otherwise valid Phase 3 artifact fail validation.
        finding["protocol"] = (
            "udp" if service in {"coap", "snmp", "bacnet"}
            else "tcp" if service else ""
        )
    if service in {"http", "https"}:
        endpoints = _extract_endpoint_paths(
            finding.get("endpoints"), finding.get("endpoint"),
            finding.get("details"), finding.get("evidence"),
        )
        if endpoints:
            finding["endpoints"] = endpoints
            if not str(finding.get("endpoint", "")).strip():
                finding["endpoint"] = endpoints[0]
    if not str(finding.get("endpoint", "")).strip():
        text = f"{finding.get('details', '')} {finding.get('evidence', '')}"
        match = re.search(r"https?://[^\s,]+", text)
        if match:
            finding["endpoint"] = urlsplit(match.group(0).rstrip(".)'\"")).path or "/"
    finding.setdefault("product", "")
    finding.setdefault("version", "")
    return finding
