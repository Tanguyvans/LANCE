"""Finding normalization and semantic rejection policy.

Independent of pipeline execution, providers and filesystem access. These
rules preserve raw observations and govern their canonical publication;
they are not a substitute for execution evidence or schema validation.
"""
from __future__ import annotations

import re

from src.agent.vuln_taxonomy import canonicalize

_WEB_SERVICES = frozenset({"http", "https", "web", "websocket", "mqtt-ws"})

_WEB_PORTS = frozenset({80, 443, 8000, 8080, 8081, 8443, 8888, 9001})

_TLS_SERVICES = frozenset({"https", "tls", "mqtts", "imaps", "ldaps"})

_INSECURE_PROTOCOL_SERVICES = frozenset({
    "telnet", "ftp", "mqtt", "rtsp", "bacnet", "modbus", "s7comm",
    "ethernet/ip", "opcua", "coap",
})

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
    context_findings = context_findings or []
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

    if vuln_type == "directory_listing" and (
        re.search(
            r"(?i)(?:backup|\.sql|\.env|/config|credential|password|secret|api[_ -]?key)",
            text,
        )
        or any(
            other is not finding
            and other.get("device_ip") == finding.get("device_ip")
            and canonicalize(str(other.get("type") or "")) == "data_exposure"
            and re.search(
                r"(?i)(?:backup|\.sql|\.env|/config|credential|password|secret|api[_ -]?key)",
                " ".join(
                    str(other.get(key) or "")
                    for key in ("details", "evidence", "endpoint", "endpoints")
                ),
            )
            for other in context_findings
        )
    ):
        finding["type"] = "data_exposure"
        finding["_semantic_origin"] = "sensitive_directory_listing"
        return

    if (
        vuln_type == "directory_listing"
        and device_role.casefold() in {"iot_gateway", "gateway"}
        and service in {"http", "https"}
        and re.search(r"(?i)(?:^|[ /])firmware/?(?:\b|$)", text)
        and re.search(
            r"(?i)(?:unsigned|without (?:a )?(?:signature|signature verification|"
            r"authentication)|no \.(?:sha256|sha512|sig|asc)\b|"
            r"update (?:endpoint|request).{0,80}(?:accepted|allowed)|"
            r"/update.{0,80}\b(?:200|201|202|204)\b)",
            text,
        )
    ):
        # Only map a firmware listing to the OTA contract when the evidence
        # also proves missing integrity/authentication controls.
        finding["type"] = "insecure_update"
        finding["severity"] = "HIGH"
        finding["_semantic_origin"] = "firmware_listing_as_ota_surface"
        return

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

    if (
        vuln_type == "no_auth"
        and (service == "mqtt" or port in {1883, 8883})
        and re.search(r"(?i)(?:test\s*:\s*test|username\s*=\s*test|weak default credentials)", text)
        and not re.search(r"(?i)(?:anonymous|without authentication|no authentication)", text)
    ):
        finding["type"] = "default_credentials"
        finding["_semantic_origin"] = "authenticated_weak_credentials"
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
    try:
        port = int(finding.get("port"))
    except (TypeError, ValueError):
        port = None

    details = " ".join(
        str(finding.get(key) or "")
        for key in ("details", "evidence", "endpoint", "endpoints", "product", "version")
    ).casefold()
    context_findings = context_findings or []
    role = device_role.casefold()

    # The S15 API fixtures answer unknown paths with a generic 200 body. The
    # 24/08 run shows that a model can mistake that fixture response for RCE,
    # credentials, OTA, and access-control flaws. Keep model candidates in the
    # raw registry, but require the exact role contract before publication.
    if not compact and source_kind == "model":
        endpoint_path = str(finding.get("endpoint") or "").casefold().rstrip("/") or "/"

        # S17-S19 have deliberately sparse contracts. Their deterministic
        # probes below are the publication boundary; generic HTTP fixture
        # claims from the model are not evidence for these roles.
        if role in {
            "ota_repository", "ota_server", "ota_device", "ota_signer", "ota_monitor",
            "cloud_web_server", "cloud_metadata_server", "cloud_control_plane",
            "cloud_worker", "cloud_audit", "ot_hmi", "ot_historian",
            "ot_opcua_server", "ot_bacnet_server",
        }:
            return "role requires an explicit deterministic simulator contract marker"
        if role == "modbus_server" and service == "ssh":
            return "Modbus role cannot inherit generic SSH findings"

        # S16 PKI services return public certificates, fingerprints, status
        # objects, and generic component responses. Only the exact contract
        # marker is publishable; deterministic probes provide those markers.
        if role.startswith("pki_"):
            if (
                role == "pki_ca_server"
                and vuln_type == "data_exposure"
                and endpoint_path == "/ca/private-key"
                and re.search(r"(?i)begin(?: RSA| EC| OPENSSH)? private key", details)
            ):
                pass
            elif (
                role == "pki_enrollment_server"
                and vuln_type == "misconfiguration"
                and endpoint_path == "/enroll"
                and re.search(r"(?i)(?:two|2)\s+POST.{0,120}201|replayable|same.{0,40}bundle", details)
            ):
                pass
            elif (
                role == "pki_mtls_server"
                and vuln_type == "weak_cipher"
                and re.search(r"(?i)revoked.{0,100}(?:HTTP\s*200|accepted)|revocation_checked\s*[:=]\s*false", details)
            ):
                pass
            elif (
                role == "pki_device"
                and vuln_type == "weak_cipher"
                and re.search(r"(?i)(?:identical|cloned|same).{0,100}(?:fingerprint|public[- ]key|key material)", details)
            ):
                pass
            else:
                return "generic PKI metadata or a control response is not a scored finding"

        if role == "api_identity_server" and vuln_type in {
            "data_exposure", "broken_access_control", "insecure_protocol", "no_auth",
            "info_disclosure", "missing_header",
        }:
            return "identity API documentation/auth flow is context, not a scored defect"
        if role in {"api_data_store", "api_event_broker", "api_admin_portal"}:
            direct_marker = re.search(
                r'''(?i)(?:BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE KEY|(?:password|passwd|token|secret|api[_ -]?key)\s*["']?\s*[:=]\s*["']?[A-Za-z0-9_./:+=-]{3,}|uid=\d+|["'](?:tenants?|devices|access_token)["']\s*:)''',
                details,
            )
            if not direct_marker:
                return "generic API fixture response is not proof of a vulnerability"
        if role == "api_tenant_server" and vuln_type == "broken_access_control":
            allowed_endpoints = {
                "/v1/devices/device-a", "/v1/devices/device-b", "/v1/admin/export",
            }
            if endpoint_path not in allowed_endpoints or not re.search(
                r"(?i)(?:bearer|tenant|owner_id|role|scope|HTTP\s+200)",
                details,
            ):
                return "tenant authorization finding lacks a bounded route and response proof"
        elif role == "api_tenant_server" and vuln_type in {
            "data_exposure", "no_auth", "code_injection", "insecure_update",
        } and endpoint_path not in {
            "/v1/devices/device-a", "/v1/devices/device-b", "/v1/admin/export",
        }:
            return "tenant API finding targets a route outside the authorization contract"

    if not compact and vuln_type == "info_disclosure" and service in {"http", "https"}:
        endpoint_path = str(finding.get("endpoint") or "").casefold().rstrip("/") or "/"
        if (
            endpoint_path in {"/health", "/status", "/docs", "/protocol"}
            and not re.search(
                r"(?i)(?:password|credential|secret|token|api[_ -]?key|private key|authorization|topology)",
                details,
            )
        ):
            return "generic health/docs metadata is not a scored disclosure"

    if (
        not compact
        and vuln_type == "code_injection"
        and service in {"http", "https"}
        and re.search(r"(?i)(?:/api/exec|rce endpoint|command execution)", details)
        and not re.search(r"(?i)(?:uid=\d+|command\s+(?:output|result)|executed|shell\s+opened|rce\s+confirmed)", details)
    ):
        return "HTTP endpoint presence does not prove command execution"

    if not compact and vuln_type == "no_auth":
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

    if (
        not compact
        and vuln_type == "misconfiguration"
        and service == "ssh"
        and device_role.casefold() == "ssh_server_v2"
        and re.search(r"(?i)(?:private key|id_rsa|id_ed25519|authorized_keys|world[- ]readable|permissions?)", details)
        and not re.search(r"(?i)(?:id_(?:rsa|ed25519)|authorized_keys).{0,100}(?:\b0?644\b|world[- ]readable)|(?:\b0?644\b|world[- ]readable).{0,100}(?:id_(?:rsa|ed25519)|authorized_keys)", details)
    ):
        return "SSH key exposure claim lacks direct path and permission evidence"

    if not compact and vuln_type == "misconfiguration":
        if re.search(
            r"(?i)(?:no evidence of\s+allowtcpforwarding|may allow unrestricted|"
            r"might allow|could allow|potentially enables)",
            details,
        ) and not re.search(
            r"(?i)(?:allowtcpforwarding\s*=\s*(?:yes|on)|forwarding\s+"
            r"(?:is|was)\s+(?:enabled|permitted)|world[- ]readable|"
            r"permissions?\s*[:=]\s*[0-7]{3,4}|iptables|firewall)",
            details,
        ):
            return "speculative configuration claim lacks direct configuration evidence"

    if not compact and vuln_type == "insecure_protocol" and service in {
        "modbus", "s7comm", "ethernet/ip", "opcua"
    } and re.search(
        r"(?i)(?:protocol specification lacks|no inherent authentication|"
        r"no inherent security|plaintext and unauthenticated)",
        details,
    ) and not re.search(
        r"(?i)(?:read(?:_|-| )?register|write(?:_|-| )?register|"
        r"response|slave\s+id|successful|accepted)",
        details,
    ):
        return "protocol properties alone do not prove an additional vulnerability"

    if not compact and vuln_type == "insecure_protocol" and service in {
        "modbus", "s7comm", "ethernet/ip", "opcua"
    } and any(
        other is not finding
        and other.get("device_ip") == finding.get("device_ip")
        and canonicalize(str(other.get("type") or "").casefold()) == "no_auth"
        and other.get("port") == finding.get("port")
        for other in context_findings
    ):
        return "industrial protocol properties are represented by the proven no_auth finding"

    if not compact and vuln_type == "misconfiguration" and service == "redis":
        if re.search(r"(?i)\bbind(?: address)?\s*[:=]?\s*0\.0\.0\.0", details) and any(
            other is not finding
            and other.get("device_ip") == finding.get("device_ip")
            and canonicalize(str(other.get("type") or "").casefold()) == "no_auth"
            for other in context_findings
        ):
            return "Redis bind exposure is represented by the proven no_auth finding"

    if not compact and vuln_type == "no_auth" and service == "redis" and re.search(
        r"(?i)(?:NOAUTH|authentication required|requirepass|password required)", details
    ) and not re.search(
        r"(?i)(?:PONG|without authentication|no password|no requirepass|unauthenticated)", details
    ):
        return "Redis NOAUTH response proves the authentication control, not no_auth"

    if not compact and vuln_type == "data_exposure" and service == "redis":
        if not re.search(
            r"(?i)(?:GET\s+[^\s]+.{0,100}(?:returned|value)|(?:retrieved|dumped|returned|captured).{0,80}(?:password|token|secret|credential|api[_ -]?key)|config:(?:db_)?password|db0:keys=\d+)",
            details,
        ):
            if re.search(r"(?i)\b(?:may|might|could|likely|possibly|potentially)\b", details):
                return "speculative data exposure lacks directly retrieved Redis content"
            return "Redis data exposure requires a retrieved sensitive key or value"

    if not compact and vuln_type == "info_disclosure" and service == "redis":
        if re.search(r"(?i)\b(?:redis\s+)?info\b|\b(?:version|architecture|memory usage|process id)\b", details) and any(
            other is not finding
            and other.get("device_ip") == finding.get("device_ip")
            and canonicalize(str(other.get("type") or "").casefold()) == "no_auth"
            for other in context_findings
        ):
            return "Redis INFO fingerprinting is redundant with the proven no_auth finding"

    if (
        not compact
        and vuln_type in {"info_disclosure", "data_exposure"}
        and device_role.casefold() == "pki_device"
        and re.search(r"(?i)/identity/(?:certificate|fingerprint)", details)
    ):
        return "PKI certificate or fingerprint metadata is not sensitive exposure"

    if not compact and vuln_type == "info_disclosure":
        if re.search(
            r"(?i)(?:port .*\bclosed\b|connection errors?|return_code\s*7|"
            r"service appears to be down|mac address.*(?:proxmox|virtual)|"
            r"virtualization platform|reveals implementation details|"
            r"slave\s+id|\bpymodbus\b|generic fingerprint(?:ing)?)",
            details,
        ):
            return "service state or generic platform fingerprint is not a scored disclosure"

        if re.search(
            r"(?i)(?:does not reveal|doesn't reveal|does not expose|"
            r"no version(?: number)? exposed|positive security practice|"
            r"prefill(?:s|ed)? .*\b(?:root|admin)\b)",
            details,
        ):
            return "a negated or prefilled value is not a security disclosure"

    if not compact and vuln_type == "broken_access_control" and not re.search(
        r"(?i)(?:idor|cross[- ]tenant|authorization(?: boundary)?\s+bypass|"
        r"access[- ]control\s+bypass|mass assignment|privileged?\s+(?:route|field)|"
        r"scope\s+bypass|unauthorized\s+(?:admin|privileged)\s+access)",
        details,
    ):
        return (
            "broken_access_control requires an explicit authorization-boundary "
            "bypass, not an exposed credential or API key"
        )

    if not compact and vuln_type == "misconfiguration" and re.search(
        r"(?i)(?:not allowed|blocked|rate[- ]limit|authentication methods?\s+"
        r"(?:failed|error)|scanner\s+(?:blocked|denied))",
        details,
    ) and not re.search(
        r"(?i)(?:iptables|firewall|allowtcpforwarding|world[- ]readable|"
        r"permission(?:s)?\s*[:=]\s*(?:[0-7]{3,4})|securitypolicy|"
        r"configuration\s+(?:allows|permits|omits|disables))",
        details,
    ):
        return "blocked or rate-limited authentication enumeration is not a configuration finding"

    if not compact and vuln_type == "default_credentials" and service in {"http", "https"}:
        successful_auth = re.search(
            r"(?i)(?:\blogged[ ]+in\b|\bauthenticated(?:[ ]+successfully)?\b|"
            r"\b(?:login|authentication)[ ]+(?:succeeded|successful|accepted|worked|confirmed)\b|"
            r"credential(?:s)?\s+(?:accepted|worked|success)|"
            r"password\s+(?:accepted|worked)|try_credential|ssh_login)",
            details,
        )
        if re.search(r"(?i)(?:backup|\.env|/config|\.sql)", details) and not successful_auth:
            return "credentials found in a file are data_exposure, not verified default_credentials"
        if re.search(r"(?i)(?:pre[- ]fills?|discloses?|default credential pattern)", details) and not successful_auth:
            return "a default username or password displayed by a page is not a successful credential test"

        if not successful_auth:
            return "HTTP default_credentials requires a successful credential authentication"

    if not compact and vuln_type == "default_credentials" and service == "ftp":
        if re.search(r"(?i)\banonymous\b|no authentication required", details) and not re.search(
            r"(?i)(?:credential(?:s)?\s+(?:accepted|worked|success)|login\s+succeeded|authenticated)",
            details,
        ):
            return "anonymous FTP access is not proof of a default account credential"

    if not compact and vuln_type == "insecure_update" and service == "ftp":
        if not re.search(
            r"(?i)(?:update|ota|upgrade|install|replace|upload|signature|checksum)",
            details,
        ):
            return "a downloadable FTP firmware directory is not an update mechanism"

    if not compact and vuln_type == "data_exposure":
        if re.search(r"(?i)(?:/sensor/|/telemetry|sensor data|telemetry)", details) and not re.search(
            r"(?i)(?:password|credential|secret|token|api[_ -]?key|private key|database|backup|\.env)",
            details,
        ):
            return "generic sensor telemetry is not sensitive data exposure"
        if re.search(r"(?i)(?:no auth required|admin panel|page title)", details) and not re.search(
            r"(?i)(?:password|credential|secret|token|api[_ -]?key|private key|database|backup|\.env|snapshot|stream)",
            details,
        ):
            return "an unauthenticated page is no_auth, not data_exposure"

        speculative = re.search(
            r"(?i)\b(?:may|might|could|potential(?:ly)?|likely|possibly|"
            r"appears? to|suggests?)\b|can be intercepted|can be retrieved",
            details,
        )
        direct_secret = re.search(
            r"(?i)(?:password|passwd|api[_ -]?key|token|secret|private key|credential)"
            r"\s*[:=]\s*[^\s,;]+|(?:captured|returned|exposes?)"
            r".{0,80}(?:password|credential|secret|token|api[_ -]?key|private key)|"
            r"sql dump|backup file|\.env\b",
            details,
        )
        if speculative and not direct_secret:
            return "speculative data exposure lacks directly retrieved sensitive content"

        if service in {"modbus", "s7comm", "ethernet/ip", "opcua"} and not re.search(
            r"(?i)(?:read|register|coil|holding|input).{0,50}(?:returned|response|value|=|:)",
            details,
        ):
            return "industrial data exposure requires an observed register or process value"

    if not compact and vuln_type == "insecure_protocol" and service == "mqtt":
        if any(
            other.get("device_ip") == finding.get("device_ip")
            and canonicalize(str(other.get("type") or "")) in {"no_auth", "data_exposure"}
            for other in context_findings
            if other is not finding
        ):
            return "plain MQTT transport is redundant with the directly proven MQTT access finding"

    if (
        not compact
        and vuln_type == "no_auth"
        and finding.get("_semantic_origin") == "unauthenticated_api"
        and str(finding.get("endpoint") or "").casefold().rstrip("/") == "/api/status"
        and any(
            other is not finding
            and other.get("device_ip") == finding.get("device_ip")
            and str(other.get("endpoint") or "").casefold().rstrip("/") == "/api/devices"
            and canonicalize(str(other.get("type") or "")) == "no_auth"
            for other in context_findings
        )
    ):
        return "secondary API status exposure is represented by the primary API devices finding"

    if not compact and vuln_type == "missing_header":
        if device_role == "iot_gateway":
            return "generic gateway headers are lower priority than its authenticated attack surface"
        if any(
            other is not finding
            and other.get("device_ip") == finding.get("device_ip")
            and canonicalize(str(other.get("type") or "")) in {"directory_listing", "data_exposure"}
            for other in context_findings
        ):
            return "generic headers are represented by the stronger sensitive-content finding"

    if vuln_type == "weak_cipher":
        crypto_services = _TLS_SERVICES | {"ssh", "smtp", "imap", "pop3"}
        if service in _WEB_SERVICES and port not in {443, 8443}:
            return "weak_cipher requires SSH/TLS evidence, not plain HTTP"
        if service and service not in crypto_services and port not in {22, 443, 465, 587, 636, 993, 995, 8443, 8883, 4840}:
            return f"weak_cipher has no cryptographic probe for service {service}"
        if not service and port not in {22, 443, 465, 587, 636, 993, 995, 8443, 8883, 4840}:
            return f"weak_cipher has no cryptographic probe for port {port}"

    if vuln_type == "insecure_protocol":
        if service in {"ssh", "http", "https", "web", "websocket"} or port in {22, 80, 443}:
            return "insecure_protocol requires a cleartext/insecure transport, not SSH or HTTP"
        if service and service not in _INSECURE_PROTOCOL_SERVICES and port not in {21, 23, 1883, 554, 5683, 502, 102, 44818}:
            return f"insecure_protocol has no supported protocol evidence for service {service}"

    if vuln_type == "directory_listing":
        if (
            device_role.casefold() in {"iot_gateway", "gateway"}
            and service in {"http", "https"}
            and re.search(r"(?i)(?:^|[ /])firmware/?(?:\b|$)", details)
            and not re.search(
                r"(?i)(?:unsigned|without (?:a )?(?:signature|signature verification|"
                r"authentication)|no \.(?:sha256|sha512|sig|asc)\b|"
                r"update (?:endpoint|request).{0,80}(?:accepted|allowed)|"
                r"/update.{0,80}\b(?:200|201|202|204)\b)",
                details,
            )
        ):
            return "firmware listing lacks proof of missing signature or update acceptance"
        if service == "web_upload" or re.search(r"(?i)(?:^|[ /])uploads?/?", details):
            return "directory_listing is not a finding for an intentional upload surface"

    if vuln_type == "data_exposure" and re.search(
        r"(?i)(?:firmware|\.bin\b|binary image|squashfs|rootfs)", details
    ) and not re.search(
        r"(?i)(?:password|credential|secret|token|private key|api[_ -]?key|\.env|backup|database|sql)",
        details,
    ):
        return "firmware binaries alone do not prove sensitive data exposure"

    if not compact and vuln_type == "info_disclosure":
        if re.search(r"(?i)(?:weak|deprecated|insecure)\s+(?:cipher|algorithm|kex|mac)", details) and not re.search(
            r"(?i)(?:banner|version|openssh|server:)", details
        ):
            return "SSH cryptographic warnings belong to weak_cipher, not info_disclosure"
        claim_details = " ".join(
            str(finding.get(key) or "")
            for key in ("details", "evidence", "endpoint", "endpoints")
        ).casefold()
        if re.search(r"(?i)(?:elliptic curve|nist p-?256|backdoor|suspected as)", claim_details) and not re.search(
            r"(?i)(?:banner|version|openssh|server:|operating system|\bos\b)", claim_details
        ):
            return "SSH algorithm properties are not a banner or version disclosure"
        if service in {"http", "https"} and re.search(r"(?i)/api/(?:status|devices)", claim_details):
            return "unauthenticated API topology belongs to the no_auth contract"
        if re.search(r"(?i)(?:secret[_ -]?key|api[_ -]?key|password|credential|token)", claim_details) and not re.search(
            r"(?i)(?:banner|version|server:|robots\.txt|\$sys|syslocation|syscontact)", claim_details
        ):
            return "sensitive values belong to data_exposure, not generic info_disclosure"
        if device_role == "nvr_server" and service == "ssh":
            return "generic NVR SSH banner disclosure is not a prioritized finding"

    if vuln_type in {"missing_header", "directory_listing"}:
        if service and service not in _WEB_SERVICES:
            return f"{vuln_type} requires an HTTP/WebSocket service, got {service}"
        if not service and port is not None and port not in _WEB_PORTS:
            return f"{vuln_type} requires an HTTP endpoint, got port {port}"
    return ""
