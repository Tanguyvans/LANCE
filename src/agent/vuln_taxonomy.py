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
    # info_disclosure synonyms
    "information_disclosure":     "info_disclosure",
    "banner_disclosure":          "info_disclosure",
    "server_version":             "info_disclosure",
    "version_leak":               "info_disclosure",
    # no_auth synonyms
    "no_auth_required":           "no_auth",
    "unauthenticated_access":     "no_auth",
    "missing_authentication":     "no_auth",
    # default_credentials synonyms
    "default_creds":              "default_credentials",
    "hardcoded_credentials":      "default_credentials",
    "default_password":           "default_credentials",
    # CVE synonyms — all collapse to the canonical `known_cve`
    "vulnerable_version":         "known_cve",
    "vulnerable_component":       "known_cve",
    "vulnerable_service":         "known_cve",
    "outdated_software":          "known_cve",
    "ssh_vulnerability":          "known_cve",
    "cve":                        "known_cve",
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
