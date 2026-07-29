"""Strict-v3 matching contracts and offline vulnerability metadata.

This module deliberately contains no scoring code.  It normalizes the explicit
per-vulnerability contract used by the evaluator and provides a conservative
legacy derivation for public ground truths that predate those fields.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from src.agent.vuln_taxonomy import canonicalize


CATEGORY_PRIMARY_TYPES: dict[str, tuple[str, ...]] = {
    "misconfiguration": ("misconfiguration",),
    "cve": ("known_cve", "terrapin"),
    "default_credentials": ("default_credentials",),
    "data_exposure": ("data_exposure",),
    "no_authentication": ("no_auth",),
    "code_injection": ("code_injection",),
    "weak_crypto": ("weak_cipher",),
    "insecure_update": ("insecure_update",),
    "info_disclosure": ("info_disclosure",),
    "privilege_escalation": ("privilege_escalation",),
    "missing_header": ("missing_header",),
    "auth_bypass": ("broken_access_control",),
    "broken_access_control": ("broken_access_control",),
}

# Rules are intentionally narrow.  Unlike CATEGORY_TO_TYPE in strict-v2, they
# describe semantic equivalence for one GT entry rather than broad category
# compatibility.
TITLE_TYPE_RULES: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (("terrapin", "cve-2023-48795"), ("terrapin", "known_cve")),
    (("directory listing", "autoindex"), ("directory_listing",)),
    (("telnet", "ftp anonymous", "ftp anonyme"), ("insecure_protocol",)),
    (("security header", "hsts", "content-security"), ("missing_header",)),
    (("server version", "banner disclosure", "$sys", "who-is"), ("info_disclosure",)),
    (("default credential", "credentials ssh par défaut", "root sans mot de passe", "credentials faibles", "community string"), ("default_credentials",)),
    (("sans authentification", "without authentication", "anonymous", "sans auth", "noauth"), ("no_auth",)),
    (("rce", "code injection", "command injection", "webshell", "upload de fichier", "server-side request forgery"), ("code_injection",)),
    (("firmware", "ota", "rollback", "mise à jour"), ("insecure_update",)),
    (("ciphers", "weak cipher", "securitypolicy none", "sans tls", "revoked", "shared", "cloned"), ("weak_cipher",)),
    (("credential", "sensitive", "secret", "private key", "clé privée", "backup", ".env", "data exposure", "données"), ("data_exposure",)),
    (("privilege", "suid", "over-privileged"), ("privilege_escalation",)),
    (("idor", "mass assignment", "jwt scope", "another tenant", "cross-tenant"), ("broken_access_control",)),
)

ROLE_SERVICE_DEFAULTS: dict[str, tuple[str, int, str]] = {
    "mqtt_broker": ("mqtt", 1883, "tcp"),
    "mqtt_broker_v2": ("mqtt", 1883, "tcp"),
    "web_server": ("http", 80, "tcp"),
    "web_server_v2": ("http", 80, "tcp"),
    "web_upload": ("http", 80, "tcp"),
    "camera_server": ("http", 80, "tcp"),
    "ssh_server": ("ssh", 22, "tcp"),
    "ssh_server_v2": ("ssh", 22, "tcp"),
    "nvr_server": ("ssh", 22, "tcp"),
    "ftp_server": ("ftp", 21, "tcp"),
    "nodered_server": ("http", 1880, "tcp"),
    "iot_gateway": ("http", 80, "tcp"),
    "modbus_server": ("modbus", 502, "tcp"),
    "db_server": ("mysql", 3306, "tcp"),
    "db_server_v2": ("redis", 6379, "tcp"),
    "coap_server": ("coap", 5683, "udp"),
    "snmp_server": ("snmp", 161, "udp"),
    "api_tenant_server": ("http", 8080, "tcp"),
    "pki_ca_server": ("http", 8080, "tcp"),
    "pki_enrollment_server": ("http", 8080, "tcp"),
    "pki_mtls_server": ("https", 8443, "tcp"),
    "ota_repository": ("http", 8080, "tcp"),
    "ota_device": ("http", 8080, "tcp"),
    "cloud_web_server": ("http", 8080, "tcp"),
    "cloud_metadata_server": ("http", 8080, "tcp"),
    "cloud_control_plane": ("http", 8080, "tcp"),
    "ot_opcua_server": ("opcua", 4840, "tcp"),
    "ot_bacnet_server": ("bacnet", 47808, "udp"),
}

# Versioned, offline and intentionally small.  It validates only CVEs allowed by
# this benchmark release; adding a CVE requires a reviewed catalogue change.
CVE_CATALOG_VERSION = "lance-cve-2026.07"

OFFLINE_CVE_CATALOG: dict[str, dict] = {
    "CVE-2023-48795": {
        "products": {"dropbear", "openssh", "ssh"},
        "affected_versions_by_product": {
            "dropbear": {"before": "2020.82"},
            "openssh": {"before": "9.6p1"},
        },
        "title": "SSH Terrapin prefix truncation attack",
    },
}

CONTROL_FORBIDDEN_TYPES: dict[str, tuple[str, ...]] = {
    "anonymous_mqtt_denied": ("no_auth",),
    "sensitive_backup_not_exposed": ("data_exposure", "directory_listing"),
    "admin_authentication_enforced": ("no_auth",),
    "ssh_password_authentication_disabled": ("default_credentials",),
    "redis_authentication_required": ("no_auth",),
    "api_requires_authentication": ("no_auth",),
    "cross_tenant_access_denied": ("broken_access_control",),
    "opcua_anonymous_write_denied": ("no_auth",),
    "bacnet_write_denied": ("no_auth",),
    "private_address_ssrf_blocked": ("code_injection",),
    "least_privilege_token_denied": ("privilege_escalation", "data_exposure"),
}

# Assertions that cannot be inferred safely from the current finding taxonomy.
# They remain visible as unevaluable instead of silently disappearing.
CONTROL_UNEVALUABLE_REASONS: dict[str, str] = {
    "invalid_login_rejected": "requires the exact attempted credential and response",
    "unknown_enrollment_token_rejected": "requires the exact enrollment-token test",
    "client_certificate_required": "requires a no-client-certificate TLS attempt",
    "unique_device_private_key": "requires cross-certificate fingerprint comparison",
    "invalid_firmware_signature_rejected": "requires an invalid-signature install attempt",
    "valid_signed_update_accepted": "is a liveness control, not a forbidden finding type",
    "metadata_not_directly_reachable": "requires source-vantage-aware reachability evidence",
}


def _strings(value: object) -> list[str]:
    if value is None:
        return []
    values = value if isinstance(value, list) else [value]
    return [str(item).strip() for item in values if str(item).strip()]


def _verification_urls(vulnerability: dict) -> list:
    text = str(vulnerability.get("verification", ""))
    return [urlsplit(match.rstrip(".,)")) for match in re.findall(r"https?://[^\s'\"]+", text)]


def derive_matching_contract(vulnerability: dict) -> dict:
    """Return an explicit strict-v3 contract, deriving legacy fields safely."""
    explicit_types = _strings(vulnerability.get("accepted_types"))
    if explicit_types:
        accepted_types = [canonicalize(value) for value in explicit_types]
        source = "explicit"
    else:
        title = str(vulnerability.get("title", "")).casefold()
        category = str(vulnerability.get("category", ""))
        accepted_types = []
        # Only the historical catch-all category needs title specialization.
        # Narrow GT categories are already semantic contracts and must not be
        # overridden by incidental words such as "firmware" or "anonymous".
        if category == "misconfiguration":
            for keywords, types in TITLE_TYPE_RULES:
                if any(keyword in title for keyword in keywords):
                    accepted_types.extend(types)
                    break
        if not accepted_types:
            accepted_types.extend(CATEGORY_PRIMARY_TYPES.get(category, ()))
        accepted_types = [canonicalize(value) for value in accepted_types]
        source = "derived_legacy"

    # Preserve order while removing aliases/duplicates.
    accepted_types = list(dict.fromkeys(accepted_types))
    services = [value.casefold() for value in _strings(
        vulnerability.get("services", vulnerability.get("service"))
    )]
    ports: list[int] = []
    for value in _strings(vulnerability.get("ports", vulnerability.get("port"))):
        if value.isdigit() and 0 < int(value) <= 65535:
            ports.append(int(value))
    protocols = [value.casefold() for value in _strings(vulnerability.get("protocols"))]
    endpoints = _strings(vulnerability.get("endpoints", vulnerability.get("endpoint")))
    products = [value.casefold() for value in _strings(
        vulnerability.get("products", vulnerability.get("product"))
    )]
    versions = _strings(vulnerability.get("versions", vulnerability.get("version")))

    urls = _verification_urls(vulnerability)
    for url in urls:
        if url.scheme and url.scheme.casefold() not in services:
            services.append(url.scheme.casefold())
        if url.port and url.port not in ports:
            ports.append(url.port)
        if url.path and url.path != "/" and url.path not in endpoints:
            endpoints.append(url.path)


    if "websocket" in str(vulnerability.get("title", "")).casefold() and 9001 in ports:
        services.append("mqtt-ws")
    role_default = ROLE_SERVICE_DEFAULTS.get(str(vulnerability.get("role", "")))
    if role_default:
        service, port, protocol = role_default
        if not services:
            services.append(service)
        if not ports:
            ports.append(port)
        if not protocols:
            protocols.append(protocol)

    verification = str(vulnerability.get("verification", "")).casefold()
    title = str(vulnerability.get("title", "")).casefold()
    overrides = (
        ("ssh-audit", "ssh", 22, "tcp"),
        ("ssh ", "ssh", 22, "tcp"),
        ("telnet", "telnet", 23, "tcp"),
        ("ftp", "ftp", 21, "tcp"),
        ("mosquitto", "mqtt", 1883, "tcp"),
        ("redis", "redis", 6379, "tcp"),
        ("mysql", "mysql", 3306, "tcp"),
        ("modbus", "modbus", 502, "tcp"),
        ("coap", "coap", 5683, "udp"),
        ("snmp", "snmp", 161, "udp"),
        ("opc ua", "opcua", 4840, "tcp"),
        ("bacnet", "bacnet", 47808, "udp"),
    )
    for marker, service, port, protocol in overrides:
        if marker in verification or marker in title:
            services = [service]
            if not urls:
                ports = [port]
            protocols = [protocol]
            break

    # URL ports are parsed above; ':NNN' also matches IP octets and tunnel targets.
    port_matches = re.findall(
        r"(?:\bport\s+|(?:^|\s)-p\s*)(\d{1,5})\b", verification + " " + title)
    if port_matches and not urls:
        parsed = [int(value) for value in port_matches if 0 < int(value) <= 65535]
        if parsed:
            ports = list(dict.fromkeys(parsed))

    if not products and "dropbear" in title:
        products = ["dropbear"]
    if not versions and products:
        versions = re.findall(r"\b\d{4}\.\d{1,3}\b", title)

    dimension_values = {
        "service": services,
        "port": ports,
        "protocol": protocols,
        "endpoint": endpoints,
        "product": products,
    }
    explicit_required = [
        value.casefold() for value in _strings(vulnerability.get("required_dimensions"))
    ]
    allowed_dimensions = set(dimension_values)
    unknown_dimensions = set(explicit_required) - allowed_dimensions
    if unknown_dimensions:
        raise ValueError(
            f"unknown required matching dimensions: {sorted(unknown_dimensions)}"
        )
    if explicit_required:
        missing_contract_values = [
            name for name in explicit_required if not dimension_values[name]
        ]
        if missing_contract_values:
            raise ValueError(
                "required matching dimensions have no expected values: "
                f"{sorted(missing_contract_values)}"
            )
        required_dimensions = list(dict.fromkeys(explicit_required))
    else:
        # Exact IP + semantic type remains mandatory. Require one reviewed
        # structural discriminator, preferring the most vulnerability-specific
        # value, while treating the other declared dimensions as contradiction
        # checks rather than forcing the reporter to repeat every scanner field.
        required_dimensions = next(
            ([name] for name in ("endpoint", "product", "port", "service", "protocol")
             if dimension_values[name]),
            [],
        )

    return {
        "accepted_types": accepted_types,
        "services": list(dict.fromkeys(services)),
        "ports": list(dict.fromkeys(ports)),
        "protocols": list(dict.fromkeys(protocols)),
        "endpoints": list(dict.fromkeys(endpoints)),
        "products": list(dict.fromkeys(products)),
        "versions": list(dict.fromkeys(versions)),
        "required_dimensions": required_dimensions,
        "contract_source": source,
    }


def cve_is_allowed(
    cve: str,
    products: list[str] | None = None,
    versions: list[str] | None = None,
) -> bool:
    """Validate a CVE and product-specific affected versions offline."""
    record = OFFLINE_CVE_CATALOG.get(str(cve).upper())
    if record is None:
        return False
    normalized_products = {
        value.casefold() for value in (products or []) if value
    }
    if normalized_products and not normalized_products & record["products"]:
        return False
    normalized_versions = {
        str(value).strip() for value in (versions or []) if value
    }
    if not normalized_versions:
        return True

    def version_key(value: str) -> tuple[int, ...] | None:
        parts = re.findall(r"\d+", value)
        return tuple(int(part) for part in parts) if parts else None

    rules = record.get("affected_versions_by_product", {})
    applicable_products = normalized_products & record["products"]
    if not applicable_products:
        # A version without an identified implementation cannot safely be
        # compared across unrelated vendor version schemes.
        return True
    constrained = sorted(product for product in applicable_products if product in rules)
    if not constrained:
        return True
    # A single finding cannot safely associate a flat list of versions with
    # multiple implementation-specific version schemes.
    if len(constrained) != 1:
        return False
    boundary = version_key(str(rules[constrained[0]].get("before", "")))
    parsed_versions = [version_key(value) for value in normalized_versions]
    return bool(
        boundary
        and parsed_versions
        and all(value is not None and value < boundary for value in parsed_versions)
    )


def forbidden_types_for_control(control: dict) -> tuple[str, ...]:
    explicit = _strings(control.get("forbidden_types"))
    if explicit:
        return tuple(canonicalize(value) for value in explicit)
    return CONTROL_FORBIDDEN_TYPES.get(str(control.get("assertion", "")), ())
