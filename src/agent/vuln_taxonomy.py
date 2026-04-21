"""Vulnerability type taxonomy shared by pipeline and evaluator.

Single source of truth for canonical vuln types, synonym aliases, config-only
classification, and Phase 4 exploit category mapping. Used by:
- `src/agent/pipeline.py` (Phase 3 aggregation, Phase 4 routing)
- `src/benchmark/evaluator.py` (matching LLM findings against ground truth)
"""

from __future__ import annotations


CANONICAL_TYPES: frozenset[str] = frozenset({
    "weak_cipher", "no_auth", "missing_header", "info_disclosure",
    "terrapin", "version_leak", "known_cve", "directory_listing",
    "data_exposure", "insecure_protocol", "default_credentials",
    "network_exposure", "insecure_update", "code_injection",
    "misconfiguration",
})


CONFIG_ONLY_TYPES: frozenset[str] = frozenset({
    "weak_cipher", "missing_header", "info_disclosure", "terrapin",
    "version_leak", "known_cve",
})


# Types that are categorically NOT vulnerabilities — they're either negations
# of findings ("no CVE applies") or meta-observations ("creds reused across
# services"). The LLM produces them when over-eager to report. Dropped during
# Phase 3 aggregation regardless of severity or evidence.
NOISE_TYPES: frozenset[str] = frozenset({
    "no_applicable_cve",
    "cross_service_auth",
    # Network topology observations (not vulns)
    "entry_point",
    "network_position",
    "service_exposure",
    "service_recon",
    "service_discrepancy",
    "exposed_service",
    # Meta-observations / negations
    "snmp_not_scanned",
    "no_http_service",
    "informational",
    "potential_cve",
    "exposure",
    # Structural FPs
    "cross_service",
    "network_exposure_generic",
    # Over-eager LLM reporting
    "firmware_exposure",
    "firmware_update_no_auth",
    "weak_protocol",
    "suspected_cve",
    # Pivot/lateral movement observations (not vulnerabilities per se)
    "pivot_enabler",
    "pivot_opportunity",
    "pivot_risk",
    # Hallucinated or ambiguous types
    "protocol_weakness",
    "protocol_vulnerability",
    "vulnerable_cve",
    "firmware_no_signature",
    "firmware_tampering",
    "dos",
    "cve_mqtt_null_deref",
    "unpatched_software",
    "network_exposure",
    # XSS / injection noise (require manual app-layer testing, not network scanner)
    "xss",
    "xss_stored",
    "prototype_pollution",
    # Nonsensical device-type names used as vuln types by LLM
    "ssh_server",
    "web_server",
    "ssh_weak_ciphers",
    # API/key exposure duplicates (already covered by data_exposure)
    "api_key_exposed",
    "smtp_credentials_exposed",
    # Pivot/lateral movement observations (continued)
    "pivot_capability",
    # Firmware update noise (different from insecure_update which is canonical)
    "firmware_ota_no_sig",
    # Weak credential as standalone type (covered by default_credentials alias)
    "weak_credential",
    # Privilege management / OT protocol observations
    "improper_privilege_management",
    "weak_protocol_design",
    "missing_cryptographic_authentication",
    "denial_of_service",
})


EXPLOIT_CATEGORY_MAP: dict[str, str] = {
    "default_credentials": "credentials",
    "code_injection":      "injection",
    "insecure_update":     "injection",
    "no_auth":             "data_access",
    "data_exposure":       "data_access",
    "directory_listing":   "data_access",
    "insecure_protocol":   "data_access",
    "network_exposure":    "data_access",
    "misconfiguration":    "data_access",
}


VULN_TYPE_ALIASES: dict[str, str] = {
    # data_exposure synonyms
    "credentials_exposed":        "data_exposure",
    "credentials_exposure":       "data_exposure",
    "credential_exposure":        "data_exposure",
    "api_key_exposure":           "data_exposure",
    "cross_service_credentials":  "data_exposure",
    "cross_service_correlation":  "data_exposure",
    "credential_reuse":           "data_exposure",
    "plaintext_credentials":      "data_exposure",
    "config_exposure":            "data_exposure",
    "sensitive_data_exposure":    "data_exposure",
    "file_disclosure":            "data_exposure",
    "firmware_disclosure":        "data_exposure",
    "sensitive_file_exposure":    "data_exposure",
    # weak_cipher synonyms
    "ssh_weak_config":            "weak_cipher",
    "weak_ssh_config":            "weak_cipher",
    "weak_config":                "weak_cipher",
    "weak_key_exchange":          "weak_cipher",
    "weak_kex":                   "weak_cipher",
    "weak_mac":                   "weak_cipher",
    "insecure_cipher":            "weak_cipher",
    "deprecated_cipher":          "weak_cipher",
    "weak_encryption":            "weak_cipher",
    "ssh_terrapin_partial":       "weak_cipher",
    "ssh_weak_key_exchange":      "weak_cipher",
    "missing_encryption":         "weak_cipher",
    # info_disclosure synonyms
    "information_disclosure":     "info_disclosure",
    "banner_disclosure":          "info_disclosure",
    "server_version":             "info_disclosure",
    "version_leak":               "info_disclosure",
    # no_auth synonyms
    "no_auth_required":           "no_auth",
    "unauthenticated_access":     "no_auth",
    "missing_authentication":     "no_auth",
    "weak_authentication":        "no_auth",
    "missing_auth":               "no_auth",
    "authentication":             "no_auth",
    "api_exposure":               "no_auth",
    # default_credentials synonyms
    "default_creds":                    "default_credentials",
    "hardcoded_credentials":            "default_credentials",
    "default_password":                 "default_credentials",
    "default_credentials_exposed":      "default_credentials",
    "weak_credentials":                 "default_credentials",
    "default_credentials_suspected":    "default_credentials",
    "suspected_default_credentials":    "default_credentials",
    # no_auth synonyms
    "no_authentication":                "no_auth",
    # misconfiguration synonyms
    "configuration":              "misconfiguration",
    "insecure_configuration":     "misconfiguration",
    # CVE synonyms — all collapse to the canonical `known_cve`
    "vulnerable_version":         "known_cve",
    "vulnerable_component":       "known_cve",
    "vulnerable_service":         "known_cve",
    "outdated_software":          "known_cve",
    "ssh_vulnerability":          "known_cve",
    "cve":                        "known_cve",
    "CVE":                        "known_cve",
    "vulnerability":              "known_cve",
    # directory_listing synonyms
    "open_directory":             "directory_listing",
    "autoindex":                  "directory_listing",
    # insecure_update synonyms
    "insecure_firmware_update":   "insecure_update",
    "unsigned_firmware":          "insecure_update",
    "ota_no_signature":           "insecure_update",
    # code_injection synonyms (file upload without validation)
    "file_upload_endpoint":       "code_injection",
    "unrestricted_file_upload":   "code_injection",
    "arbitrary_file_upload":      "code_injection",
    # weak_cipher synonyms (continued)
    "weak_cipher_ssh":            "weak_cipher",
}


def canonicalize(vuln_type: str) -> str:
    """Return the canonical form of a vuln type, mapping known aliases."""
    return VULN_TYPE_ALIASES.get(vuln_type, vuln_type)


def is_config_only(vuln_type: str) -> bool:
    """True if the type is a configuration observation that never triggers a Phase 4 exploit agent."""
    return canonicalize(vuln_type) in CONFIG_ONLY_TYPES


def is_noise(vuln_type: str) -> bool:
    """True if the type is categorically not a vuln (LLM over-reporting noise)."""
    return vuln_type in NOISE_TYPES


def exploit_category(vuln_type: str) -> str | None:
    """Return the Phase 4 exploit category for a vuln type, or None if none applies."""
    return EXPLOIT_CATEGORY_MAP.get(canonicalize(vuln_type))
