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
    "misconfiguration", "privilege_escalation",
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
    # Service-type names used as vuln types by LLM (the service IS not the vuln)
    "ssh_server",
    "web_server",
    "ssh_weak_ciphers",
    "mqtt_broker",
    "mqtt_server",
    "rtsp_server",
    "coap_server",
    "ftp_server",
    "modbus_server",
    "http_server",
    "snmp_server",
    "redis_server",
    "nodered_server",
    "camera_server",
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
    # Process / OS configuration observations (not network vulns)
    "process_running_as_root",
    "redis_running_as_root",
    "running_as_root",
    "root_process",
    # Firmware exposure — already covered by insecure_update
    "firmware_accessible",
    "firmware_download",
    "firmware_binary_exposed",
    # MQTT auth observations that are not actual data leaks
    "mqtt_auth_required",
    "mqtt_weak_auth",
    # Generic "might be vulnerable" noise
    "potential_vulnerability",
    "suspected_vulnerability",
    "unverified_vulnerability",
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
    "privilege_escalation":"injection",
}


VULN_TYPE_ALIASES: dict[str, str] = {
    # data_exposure synonyms
    "snapshot_accessible":        "data_exposure",
    "stream_accessible":          "data_exposure",
    "unauthenticated_stream":     "data_exposure",
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
    "weak_crypto":                "weak_cipher",
    "weak_cryptographic_implementation": "weak_cipher",
    "weak_tls":                   "weak_cipher",
    "insecure_tls":               "weak_cipher",
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
    "unauthenticated_rtsp":       "no_auth",
    "unauthenticated_mqtt":       "no_auth",
    "unauthenticated_coap":       "no_auth",
    "unauthenticated_modbus":     "no_auth",
    "anonymous_access":           "no_auth",
    "weak_auth":                  "no_auth",
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
    "coap_no_dtls":                     "no_auth",
    "modbus_no_auth":                   "no_auth",
    "mqtt_no_auth":                     "no_auth",
    "redis_no_auth":                    "no_auth",
    "http_no_auth":                     "no_auth",
    "camera_no_auth":                   "no_auth",
    "gateway_no_auth":                  "no_auth",
    # weak_cipher synonyms (LDAP/TLS)
    "ldap_no_tls":                      "weak_cipher",
    "ldap_cleartext":                   "weak_cipher",
    "cleartext_ldap":                   "weak_cipher",
    "insecure_ldap":                    "weak_cipher",
    "no_tls":                           "weak_cipher",
    "no_dtls":                          "weak_cipher",
    # misconfiguration synonyms
    "configuration":              "misconfiguration",
    "insecure_configuration":     "misconfiguration",
    "port_forwarding":            "misconfiguration",
    "ssh_port_forwarding":        "misconfiguration",
    "tcp_forwarding":             "misconfiguration",
    "allow_tcp_forwarding":       "misconfiguration",
    "unrestricted_forwarding":    "misconfiguration",
    "world_readable":             "misconfiguration",
    "world_readable_file":        "misconfiguration",
    "insecure_file_permissions":  "misconfiguration",
    "firewall_misconfiguration":  "misconfiguration",
    "incomplete_firewall_rules":  "misconfiguration",
    "iptables_bypass":            "misconfiguration",
    "network_segmentation_bypass": "misconfiguration",
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
    # insecure_protocol synonyms
    "ftp_anonymous":              "insecure_protocol",
    "anonymous_ftp":              "insecure_protocol",
    "cleartext_ftp":              "insecure_protocol",
    "telnet_open":                "insecure_protocol",
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
    # insecure_update synonyms (continued)
    "firmware_no_auth":           "insecure_update",
    "ota_no_auth":                "insecure_update",
    "firmware_update_unauthenticated": "insecure_update",
    # no_auth synonyms (continued)
    "passwordless_root":          "no_auth",
    "root_no_password":           "no_auth",
    "empty_password":             "no_auth",
    # code_injection synonyms (exec node / command exec)
    "command_execution":          "code_injection",
    "os_command_injection":       "code_injection",
    "rce":                        "code_injection",
    "remote_code_execution":      "code_injection",
    "exec_node":                  "code_injection",
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
