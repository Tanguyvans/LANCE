"""Finding normalization and semantic rejection policy.

Independent of pipeline execution, providers and filesystem access. These
rules preserve raw observations and govern their canonical publication;
they are not a substitute for execution evidence or schema validation.
"""
from __future__ import annotations

import re

from src.agent.vuln_taxonomy import canonicalize

_WEB_SERVICES = frozenset({"http", "https", "web", "websocket", "mqtt-ws"})

def normalise_full_finding_semantics(
    finding: dict,
    context_findings: list[dict] | None = None,
    *,
    device_role: str = "",
) -> None:
    """Normalize equivalent claims before strict-v3 publication.

    This is deliberately a semantic projection, not a tool or autonomy
    restriction. The original candidate remains in the raw registry.
    """
    vuln_type = canonicalize(str(finding.get("type") or "").casefold())
    service = str(finding.get("service") or "").casefold()
    try:
        port = int(finding.get("port"))
    except (TypeError, ValueError):
        port = None
    text = " ".join(
        str(finding.get(key) or "")
        for key in ("details", "evidence", "endpoint", "endpoints")
    ).casefold()

    if (
        vuln_type == "misconfiguration"
        and service == "ssh"
        and re.search(
            r"(?i)(?:terrapin|cbc|hmac[- ]?sha-?1|sha-?1|weak\s+(?:cipher|algorithm|mac|kex))",
            text,
        )
    ):
        # Cryptographic SSH claims map to the strict-v3 weak_cipher contract.
        finding["type"] = "weak_cipher"
        finding["_semantic_origin"] = "ssh_cryptographic_misconfiguration"
        return

    if (
        vuln_type == "insecure_protocol"
        and (service == "coap" or port == 5683)
        and re.search(r"(?i)(?:dtls|cleartext|cleartext|unencrypt|plaintext)", text)
    ):
        # The benchmark contract treats CoAP without DTLS as a network
        # configuration failure, not as a generic cleartext protocol finding.
        finding["type"] = "misconfiguration"
        finding["_semantic_origin"] = "coap_without_dtls"
        return

    endpoint = str(finding.get("endpoint") or "").casefold()
    if (
        vuln_type == "info_disclosure"
        and service in {"http", "https"}
        and (endpoint.startswith("/api/") or re.search(r"(?i)/api/(?:status|devices)", text))
        and re.search(r"(?i)(?:without authentication|without auth|no auth|unauthenticated)", text)
    ):
        finding["type"] = "no_auth"
        finding["_semantic_origin"] = "unauthenticated_api"

def finding_semantic_issue(
    finding: dict, *, source_kind: str = "", compact: bool = False,
    device_role: str = "",
    context_findings: list[dict] | None = None,
) -> str:
    """Return a deterministic metadata contradiction for a model finding.

    The raw candidate registry remains the source of truth for auditing model
    output. Only contradictions that make the claimed finding impossible on
    the declared endpoint are excluded from the canonical queue.
    """
    vuln_type = canonicalize(str(finding.get("type") or "").casefold())
    service = str(finding.get("service") or "").strip().casefold()
    details = " ".join(
        str(finding.get(key) or "")
        for key in ("details", "evidence", "endpoint", "endpoints", "product", "version")
    ).casefold()

    if vuln_type == "no_auth":
        # A login page, 401/403 response, or an explicit authentication
        # requirement contradicts an unauthenticated-access claim unless the
        # same evidence proves a separate unauthenticated endpoint.
        if (
            re.search(
                r"(?i)(?:\b(?:401|403)\b|authentication required|requires authentication|"
                r"requires auth|login required)",
                details,
            )
            and not re.search(
                r"(?i)(?:no auth(?:entication)? required|without auth(?:entication)?|"
                r"unauthenticated (?:access|request|endpoint)|anonymous (?:access|login|connection))",
                details,
            )
        ):
            return "authentication is required by the observed response; no_auth is contradicted"

    if vuln_type == "no_auth" and service == "redis" and re.search(
        r"(?i)(?:NOAUTH|authentication required|requirepass|password required)", details
    ) and not re.search(
        r"(?i)(?:PONG|without authentication|no password|no requirepass|unauthenticated)", details
    ):
        return "Redis NOAUTH response proves the authentication control, not no_auth"

    if vuln_type == "weak_cipher":
        if service in {"http", "web"}:
            return "weak_cipher requires SSH/TLS evidence, not plain HTTP"

    if vuln_type == "insecure_protocol":
        if service in {"ssh", "https"}:
            return "insecure_protocol requires a cleartext/insecure transport, not SSH or HTTPS"

    if vuln_type in {"missing_header", "directory_listing"}:
        if service and service not in _WEB_SERVICES:
            return f"{vuln_type} requires an HTTP/WebSocket service, got {service}"
    return ""
