"""Benchmark evaluator — compare LLM findings against ground truth.

Usage:
    python3 -m src.benchmark.evaluator --run-dir output/agent/20250326_120000 \
        --ground-truth benchmarks/ground_truth/scenario_2.yaml \
        --output results/evaluation.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from datetime import date
from urllib.parse import urlsplit
from collections import Counter

import yaml
import networkx as nx

from src.agent.vuln_taxonomy import canonicalize, is_config_only, NOISE_TYPES
from src.benchmark.strict_v3 import (
    CONTROL_UNEVALUABLE_REASONS,
    OFFLINE_CVE_CATALOG,
    cve_is_allowed,
    derive_matching_contract,
    forbidden_types_for_control,
)
from src.benchmark.metric_contract import (
    EVIDENCE_CONTRACT_VERSION,
    METRIC_CONTRACT_VERSION,
)


# ── Evaluation policies ───────────────────────────────────────────────────────

@dataclass(frozen=True)
class EvaluationPolicy:
    """Matching/scoring behaviour for a benchmark evaluation.

    ``legacy-v1`` preserves historical scores. ``strict-v2`` is intended for
    new benchmark results: CVEs are target-bound, loose IP+severity matching is
    disabled, and unmatched "common" findings are not silently auto-bonused.
    """

    name: str
    require_cve_same_ip: bool
    allow_loose_match: bool
    allow_auto_bonus: bool
    use_explicit_contracts: bool = False
    min_match_credit: float = 0.0
    require_traceable_bonus: bool = False
    severity_in_primary_score: bool = False


LEGACY_V1 = EvaluationPolicy(
    name="legacy-v1",
    require_cve_same_ip=False,
    allow_loose_match=True,
    allow_auto_bonus=True,
)
STRICT_V2 = EvaluationPolicy(
    name="strict-v2",
    require_cve_same_ip=True,
    allow_loose_match=False,
    allow_auto_bonus=False,
)
STRICT_V3 = EvaluationPolicy(
    name="strict-v3",
    require_cve_same_ip=True,
    allow_loose_match=False,
    allow_auto_bonus=False,
    use_explicit_contracts=True,
    min_match_credit=0.5,
    require_traceable_bonus=True,
    severity_in_primary_score=True,
)

EVALUATION_POLICIES: dict[str, EvaluationPolicy] = {
    LEGACY_V1.name: LEGACY_V1,
    STRICT_V2.name: STRICT_V2,
    STRICT_V3.name: STRICT_V3,
}


def resolve_policy(policy: str | EvaluationPolicy) -> EvaluationPolicy:
    """Resolve a policy name while failing closed on unknown policy values."""
    if isinstance(policy, EvaluationPolicy):
        return policy
    try:
        return EVALUATION_POLICIES[policy]
    except KeyError as exc:
        choices = ", ".join(sorted(EVALUATION_POLICIES))
        raise ValueError(f"Unknown evaluation policy '{policy}' (expected one of: {choices})") from exc


# ── CVE year sanity ─────────────────────────────────────────────────────────────

_CVE_YEAR_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _cve_is_suspicious(cve: str) -> bool:
    """Return True if the CVE ID has a year in the future."""
    if not _CVE_YEAR_RE.match(cve):
        return False
    year_str = cve.split("-")[1]
    try:
        year = int(year_str)
        return year > date.today().year
    except ValueError:
        return False


def _sanitize_cve_ids(cve_ids: list) -> list:
    """Remove CVEs with future years (hallucinated or wrong)."""
    return [c for c in cve_ids if not _cve_is_suspicious(c)]


# ── Severity normalisation ────────────────────────────────────────────────────

SEVERITY_RANK = {
    "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0,
    "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0,
}

# Ground-truth category → LLM vuln type(s)
# Each set covers the common ways LLMs describe this category of vulnerability.
CATEGORY_TO_TYPE = {
    "misconfiguration":    {
        "no_auth", "missing_header", "version_leak", "misconfiguration",
        "insecure_protocol", "weak_config", "insecure_config", "open_service",
        "cleartext", "insecure_default", "telnet", "ftp_anonymous",
        "open_port", "service_exposure", "coap_no_dtls", "snmp_default",
        "redis_no_auth", "nodered_no_auth", "world_readable",
        "directory_listing", "insecure_update", "coap_no_auth",
    },
    "cve":                 {
        "known_cve", "terrapin", "weak_cipher", "outdated_software",
        "unpatched_vulnerability", "vulnerable_version", "known_vulnerability",
        "cve", "ssh_vulnerability",
    },
    "default_credentials": {
        "no_auth", "default_credentials", "weak_password", "hardcoded_credentials",
        "default_password", "brute_force", "weak_auth", "credential_reuse",
        "default_creds", "snmp_community", "weak_credentials",
    },
    "data_exposure":       {
        "missing_header", "version_leak", "data_exposure",
        "directory_listing", "credential_exposure", "sensitive_data_exposure",
        "info_disclosure", "config_exposure", "file_disclosure",
        "plaintext_credentials", "cleartext_storage", "backup_exposure",
    },
    "no_authentication":   {
        "no_auth", "missing_header", "no_auth_required", "unauthenticated_access",
        "missing_authentication", "insecure_access", "open_access",
        "unauthenticated", "auth_bypass", "redis_no_auth", "coap_no_auth",
        "modbus_no_auth", "nodered_no_auth", "api_no_auth", "coap_no_dtls",
    },
    "code_injection":      {
        "rce", "code_injection", "upload_bypass", "no_auth",
        "file_upload", "rce_webshell", "php_injection", "command_injection",
        "unrestricted_upload", "webshell", "arbitrary_file_upload",
        "api_rce", "nodered_exec", "remote_code_execution",
    },
    "weak_crypto":         {
        "weak_cipher", "weak_mac", "weak_kex", "insecure_tls",
        "deprecated_cipher", "weak_encryption", "insecure_cipher",
        "weak_algorithm",
    },
    "insecure_update":     {
        "ota_no_signature", "update_no_auth", "no_auth", "insecure_update",
        "firmware_no_validation", "unsigned_firmware", "ota_vulnerability",
        "insecure_firmware_update",
    },
    "info_disclosure":     {
        "info_disclosure", "version_leak", "banner_disclosure",
        "server_version", "service_enumeration", "information_disclosure",
        "sys_topics", "mqtt_sys", "robots_txt", "path_disclosure",
        "snmp_disclosure", "ssdp_disclosure", "snmp_info_leak",
        "coap_discovery",
    },
    "privilege_escalation": {
        "privilege_escalation", "privesc", "suid", "cron_writable",
        "local_privilege_escalation", "setuid", "writable_script",
        "docker_escape", "container_escape",
    },
    "missing_header":      {
        "missing_header", "security_header", "missing_security_header",
        "no_hsts", "no_csp", "no_x_frame_options", "header_missing",
    },
    "auth_bypass":         {
        "auth_bypass", "jwt_none", "jwt_bypass", "authentication_bypass",
        "token_forgery", "broken_authentication", "ssrf",
        "server_side_request_forgery",
    },
    "broken_access_control": {
        "broken_access_control", "idor", "bola", "mass_assignment",
        "jwt_scope", "scope_bypass", "authorization_bypass",
        "cross_tenant_access", "improper_privilege_management",
    },
}


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class MatchResult:
    gt_id: str
    gt_title: str
    gt_device: str
    gt_ip: str
    gt_severity: str
    matched: bool
    llm_id: str = ""
    llm_type: str = ""
    llm_severity: str = ""
    match_method: str = ""        # "cve", "ip+type", "ip+category"
    severity_match: bool = False  # True if LLM severity == GT severity
    phase4_verification: str = ""  # confirmed, error, not_tested, conflict, etc.
    match_credit: float = 0.0
    structural_match: bool = False
    verification_credit: float = 0.0
    gt_hop_depth: int = 0         # Min number of network segments crossed from attacker
                                   # to reach gt_ip. 0 = direct, 1 = behind 1 firewall, etc.


# Types considered "bonus" when found on a device that already has matched vulns.
# These are real config findings a pentester WOULD report but may be absent from GT.
# Note: no_auth is included because router admin interfaces (LuCI, etc.) are real
# findings that scanners legitimately detect even when not explicitly in ground truth.
BONUS_TYPES_AUTO: set[str] = {
    "info_disclosure", "missing_header", "weak_cipher",
    "insecure_protocol", "terrapin", "version_leak",
    "no_auth",
    # CVEs found by LLM that aren't in GT are real findings a pentester would report
    "known_cve",
    # Directory listing is a real config finding often not enumerated in GT
    "directory_listing",
}


@dataclass
class EvaluationResult:
    scenario_id: str
    run_dir: str
    ground_truth_file: str

    # Evaluation protocol / scenario-level metric. Historical fields below are
    # intentionally retained for JSON/API compatibility.
    scoring_policy: str = STRICT_V2.name
    metric_contract_version: str = METRIC_CONTRACT_VERSION
    run_metric_contract_version: str | None = None
    run_evidence_contract_version: str | None = None
    evidence_contract_compatible: bool = True
    metrics_compatibility_reason: str | None = None
    split: str | None = None
    is_zero_gt: bool = False
    specificity: float | None = None
    scenario_score_pct: float | None = 0.0

    # Counts
    total_gt_vulns: int = 0
    true_positives: int = 0
    false_negatives: int = 0
    false_positives: int = 0
    bonus_findings: int = 0   # auto-detected bonus (real config findings not in GT)
    total_llm_findings: int = 0
    severity_mismatches: int = 0  # found right vuln, wrong severity

    # Legacy metrics (kept for backward compatibility)
    detection_rate: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    detection_f1: float = 0.0
    credited_true_positives: float = 0.0
    credited_precision: float = 0.0
    credited_recall: float = 0.0
    credited_f1: float = 0.0
    severity_adjusted_f1: float = 0.0
    quality_adjusted_f1: float | None = 0.0
    verified_f1: float | None = None
    hallucination_rate: float = 0.0
    raw_precision: float = 0.0
    raw_false_positives: int = 0
    unmatched_finding_rate: float = 0.0
    bonus_finding_rate: float = 0.0
    bonus_allowance: int = 0
    bonus_overflow: int = 0

    bonus_untraceable: int = 0
    bonus_cap_exceeded: int = 0
    bonus_duplicates: int = 0
    # Weighted score: critical=4, high=3, medium=2, low=1
    # ip+category (loose) matches count as 0.5x to penalise guesses
    weighted_score: float = 0.0
    max_weighted_score: int = 0
    score_pct: float = 0.0  # weighted_score / max_weighted_score * 100

    # Primary metrics for pentest quality assessment
    exploitation_coverage: float | None = 0.0  # % of TP findings with verified evidence
    tp_exploited: int = 0               # TP findings with evidence_level >= 2
    tp_detected_only: int = 0           # TP findings with evidence_level < 2
    verified_false_positives: int = 0
    phase4_candidates: int = 0
    phase4_conclusive: int = 0
    phase4_completion_rate: float | None = None
    invalid_cve_claims: int = 0
    negative_controls_total: int = 0
    malformed_cve_claims: int = 0
    unknown_cve_claims: int = 0
    inapplicable_cve_claims: int = 0
    negative_controls_declared: int = 0
    negative_controls_unevaluable: int = 0
    negative_controls_unevaluable_list: list[dict] = field(default_factory=list)
    negative_control_penalty_factor: float = 1.0
    negative_control_violations: int = 0
    negative_control_specificity: float | None = None

    # Evidence diagnostics. These do not contribute to the official scenario
    # score. ``declared`` means that the finding contains an evidence excerpt;
    # ``execution`` means that level >= 2 was derived from structured Phase 4
    # fields; ``traceable`` additionally requires a matching tool+target record
    # in tool_calls.jsonl.
    evidence_metrics_available: bool = False
    evidence_provenance_available: bool = False
    findings_with_declared_evidence: int = 0
    declared_evidence_coverage: float | None = None
    findings_with_execution_evidence: int = 0
    execution_evidence_coverage: float | None = None
    findings_with_traceable_evidence: int = 0
    traceable_evidence_coverage: float | None = None
    traceable_true_positives: int = 0
    traceable_false_positives: int = 0
    evidence_precision: float | None = None
    evidence_recall: float | None = None
    evidence_f1: float | None = None
    evidence_claims_total: int = 0
    evidence_claims_supported: int = 0
    evidence_claims_contradicted: int = 0
    evidence_claims_unverifiable: int = 0
    evidence_faithfulness: float | None = None
    evidence_macro_faithfulness: float | None = None
    evidence_faithfulness_by_kind: dict[str, float] = field(default_factory=dict)
    ambiguous_evidence_refs: int = 0
    evidence_contradiction_rate: float | None = None
    evidence_claim_assessments: list[dict] = field(default_factory=list)

    # Process and efficiency metrics. None means unavailable in an older run.
    process_metrics_schema_version: int | None = None
    process_metrics_available: bool = False
    total_cost_usd: float | None = None
    cost_is_estimate: bool | None = None
    total_tokens: int | None = None
    total_turns: int | None = None
    total_tool_calls: int | None = None
    cost_per_tp: float | None = None
    zero_tp: bool = False
    cost_per_expected_vulnerability: float | None = None
    turns_per_tp: float | None = None
    format_fallbacks: int | None = None
    format_attempts: int | None = None
    format_fallback_rate: float | None = None
    validation_failures: int | None = None
    validation_attempts: int | None = None
    validation_successes: int | None = None
    validation_success_rate: float | None = None
    total_tool_errors: int | None = None
    tool_error_rate: float | None = None
    # Deprecated field retained for JSON compatibility; no longer calculated.
    format_compliance_rate: float | None = None

    # Multi-Hop Reach (MHR) — fraction of GT vulns at depth >= k that were detected.
    # Convention: hop_depth=0 means directly reachable from the entry point;
    # hop_depth>=1 means at least one pivot / zone transition is required.
    # None when no GT entry exists at that depth (metric undefined for that scenario,
    # e.g. a flat topology has MHR_1 = MHR_2 = MHR_3 = None).
    mhr_1: float | None = None
    mhr_2: float | None = None
    mhr_3: float | None = None
    gt_at_depth: dict = field(default_factory=dict)  # {0: 5, 1: 3, 2: 1} — GT counts per depth bucket
    tp_at_depth: dict = field(default_factory=dict)  # {0: 4, 1: 2, 2: 0} — TP counts per depth bucket

    # An attack path is detected only when every GT vulnerability referenced by
    mhr_1_credited: float | None = None
    mhr_2_credited: float | None = None
    mhr_3_credited: float | None = None
    mhr_1_verified: float | None = None
    mhr_2_verified: float | None = None
    mhr_3_verified: float | None = None
    # ``vulnerabilities_used`` was matched. This remains a diagnostic metric;
    # strict-v3 uses the quality-adjusted F1; historical policies retain their
    # original primary-score semantics.
    total_attack_paths: int = 0
    attack_paths_detected: int = 0
    path_coverage: float = 0.0
    # Unlike historical path_coverage, this requires an ordered Phase-5 chain.
    verified_path_coverage: float | None = None
    verified_attack_paths: int = 0
    intrusion_paths_available: bool = False
    path_matches: list[dict] = field(default_factory=list)

    # Details
    matches: list[dict] = field(default_factory=list)
    unmatched_llm: list[dict] = field(default_factory=list)
    quality_path_coverage: float | None = 0.0
    quality_attack_path_credit: float = 0.0
    bonus_findings_list: list[dict] = field(default_factory=list)

    # LLM Judge data
    judge_model: str | None = None
    llm_judge_data: dict | None = None


# ── Matching logic ────────────────────────────────────────────────────────────

def _match_by_cve(
    gt_vuln: dict,
    llm_findings: list[dict],
    *,
    require_same_ip: bool = False,
) -> dict | None:
    """Match a GT vulnerability by CVE ID, optionally bound to the target IP."""
    gt_cve = gt_vuln.get("cve")
    if not gt_cve:
        return None
    gt_cve_norm = gt_cve.upper()
    gt_ip = gt_vuln.get("ip", "")
    for f in llm_findings:
        if require_same_ip and (not gt_ip or f.get("device_ip", "") != gt_ip):
            continue
        llm_cves = [c.upper() for c in (f.get("cve_ids") or [])]
        if gt_cve_norm in llm_cves:
            return f
    return None


def _infer_type_from_title(title: str) -> str | None:
    """Extract an expected LLM type from the GT title keywords.

    Order matters: more specific patterns first to avoid broad matches stealing narrow ones.
    Supports both English and French GT titles.
    """
    title_lower = title.lower()
    keyword_map = [
        # ── Privilege escalation (EN + FR) ───────────────────────────────────
        ("privilege escalation", "privilege_escalation"),
        ("suid binary", "privilege_escalation"),
        ("suid", "privilege_escalation"),
        ("escalade de privilège", "privilege_escalation"),
        ("escalade", "privilege_escalation"),
        ("cron writable", "privilege_escalation"),
        # ── CVE / known vulns ────────────────────────────────────────────────
        ("terrapin", "terrapin"),
        ("cve-", "known_cve"),
        # ── Weak ciphers (EN + FR) ───────────────────────────────────────────
        ("weak cipher", "weak_cipher"),
        ("weak crypto", "weak_cipher"),
        ("weak kex", "weak_cipher"),
        ("ciphers faibles", "weak_cipher"),
        ("algorithmes faibles", "weak_cipher"),
        # ── Missing headers ──────────────────────────────────────────────────
        ("missing header", "missing_header"),
        ("security header", "missing_header"),
        ("hsts", "missing_header"),
        # ── Directory listing (EN + FR) ──────────────────────────────────────
        ("directory listing", "directory_listing"),
        ("autoindex", "directory_listing"),
        ("directory listing activé", "directory_listing"),
        ("listing activé", "directory_listing"),
        # ── Insecure protocol: Telnet / FTP / cleartext (EN + FR) ────────────
        ("telnet", "insecure_protocol"),
        ("ftp anonymous", "insecure_protocol"),
        ("ftp anonyme", "insecure_protocol"),
        # ── CoAP (EN + FR) ───────────────────────────────────────────────────
        ("coap", "coap_no_dtls"),
        ("dtls", "coap_no_dtls"),
        ("actionneur", "coap_no_auth"),
        ("actuator", "coap_no_auth"),
        ("valve", "coap_no_auth"),
        # ── OTA / firmware update (EN + FR) — before no_auth to avoid collision
        ("ota sans signature", "insecure_update"),
        ("firmware ota sans", "insecure_update"),
        ("firmware sans signature", "insecure_update"),
        ("mise à jour firmware", "insecure_update"),
        ("update without signature", "insecure_update"),
        ("insecure update", "insecure_update"),
        # ── Code injection / RCE ─────────────────────────────────────────────
        ("exec node", "code_injection"),
        ("rce", "code_injection"),
        ("command injection", "code_injection"),
        ("ssrf", "auth_bypass"),
        ("cross-tenant", "broken_access_control"),
        ("another tenant", "broken_access_control"),
        ("idor", "broken_access_control"),
        ("bola", "broken_access_control"),
        ("mass assignment", "broken_access_control"),
        ("privileged ownership fields", "broken_access_control"),
        ("jwt scope", "broken_access_control"),
        ("administrative export", "broken_access_control"),
        ("enrollment token", "misconfiguration"),
        ("token can be replayed", "misconfiguration"),
        ("revoked client certificate", "weak_cipher"),
        ("identity private key is cloned", "weak_cipher"),
        ("verification secret is shared", "weak_cipher"),
        ("firmware rollback", "insecure_update"),
        ("signed firmware rollback", "insecure_update"),
        ("obsolete signed firmware", "insecure_update"),
        ("signature does not cover", "insecure_update"),
        ("over-privileged", "privilege_escalation"),
        ("securitypolicy none", "weak_cipher"),
        ("anonymous opc ua", "no_auth"),
        ("bacnet client can write", "no_auth"),
        ("without authorization", "no_auth"),
        ("unauthenticated write", "no_auth"),
        ("who-is exposes", "info_disclosure"),
        # ── Data exposure (EN + FR) ──────────────────────────────────────────
        ("server version", "info_disclosure"),
        ("banner disclosure", "info_disclosure"),
        ("$sys topic", "info_disclosure"),
        ("sys topic", "info_disclosure"),
        ("données sensibles", "data_exposure"),
        ("fichiers sensibles", "data_exposure"),
        ("credentials en clair", "data_exposure"),
        ("credentials réseau", "data_exposure"),
        ("clé privée", "data_exposure"),
        ("backup", "data_exposure"),
        ("fichier .env", "data_exposure"),
        ("redis", "data_exposure"),
        # ── Default credentials (EN + FR) ────────────────────────────────────
        ("default credential", "default_credentials"),
        ("default password", "default_credentials"),
        ("hardcoded password", "default_credentials"),
        ("root sans mot de passe", "default_credentials"),
        ("sans mot de passe", "default_credentials"),
        ("mariadb root", "default_credentials"),
        ("mysql root", "default_credentials"),
        # ── No-auth patterns (EN + FR) — broad, must come after specifics ─────
        ("websocket", "no_auth"),
        ("anonymous mqtt", "no_auth"),
        ("mqtt sans auth", "no_auth"),
        ("mqtt anonymous", "no_auth"),
        ("node-red", "no_auth"),
        ("nodered", "no_auth"),
        ("luci", "no_auth"),
        ("web admin", "no_auth"),
        ("admin interface", "no_auth"),
        ("admin accessible", "no_auth"),
        ("interface admin", "no_auth"),
        ("interface web admin", "no_auth"),
        ("http admin", "no_auth"),
        ("admin sans auth", "no_auth"),
        ("sans authentification", "no_auth"),
        ("without authentication", "no_auth"),
        ("sans auth", "no_auth"),
        ("api rest", "no_auth"),
        ("api sans", "no_auth"),
        ("coap", "no_auth"),
        ("bacnet", "no_auth"),
        ("caméra ip sans", "no_auth"),
        ("camera ip sans", "no_auth"),
        ("flux caméra", "no_auth"),
        ("directory traversal", "path_traversal"),
    ]
    for keyword, llm_type in keyword_map:
        if keyword in title_lower:
            return llm_type
    return None


def _match_by_ip_and_type(gt_vuln: dict, llm_findings: list[dict]) -> dict | None:
    """Match by IP + compatible type or category.

    Priority order:
    1. Exact type match from GT title keywords (e.g., title "Telnet" → prefer insecure_protocol)
    2. Exact type match from GT category (e.g., category=data_exposure → prefer type=data_exposure)
    3. Any type in the compatible set from category
    """
    gt_ip = gt_vuln.get("ip", "")
    gt_category = gt_vuln.get("category", "")
    gt_title = gt_vuln.get("title", "")
    compatible_types = CATEGORY_TO_TYPE.get(gt_category, set())

    # Pass 1: infer type from title keywords (most specific)
    inferred_type = _infer_type_from_title(gt_title)
    if inferred_type:
        for f in llm_findings:
            if f.get("device_ip") != gt_ip:
                continue
            f_type = f.get("type", "")
            if f_type == inferred_type or canonicalize(f_type) == inferred_type:
                return f

    # Pass 2: exact type match (LLM type == GT category, after canonicalization)
    for f in llm_findings:
        if f.get("device_ip") != gt_ip:
            continue
        f_type = f.get("type", "")
        if f_type == gt_category or canonicalize(f_type) == gt_category:
            return f

    # Pass 3: any type in the compatible set (after canonicalization)
    for f in llm_findings:
        if f.get("device_ip") != gt_ip:
            continue
        f_type = f.get("type", "")
        if f_type in compatible_types or canonicalize(f_type) in compatible_types:
            return f
    return None


def _match_by_ip_and_service(gt_vuln: dict, llm_findings: list[dict]) -> dict | None:
    """Loose match: same IP + exact severity (last resort).

    This compatibility fallback is intentionally half-weighted by the scorer. It
    catches tool outputs that identify the affected host and impact but use an
    unknown type string. Exact severity is required to reduce cross-vulnerability
    collisions when multiple findings share the same IP.
    """
    gt_ip = gt_vuln.get("ip", "")
    gt_sev = gt_vuln.get("severity", "low").lower()
    for f in llm_findings:
        if f.get("device_ip") != gt_ip:
            continue
        llm_sev = (f.get("severity") or "low").lower()
        if llm_sev == gt_sev:
            return f
    return None


def _normalized_values(value: object, *, integer: bool = False) -> set:
    values = value if isinstance(value, list) else [value]
    normalized = set()
    for item in values:
        if item in (None, ""):
            continue
        if integer:
            try:
                normalized.add(int(item))
            except (TypeError, ValueError):
                continue
        else:
            normalized.add(str(item).strip().casefold())
    return normalized


def _normalize_port(value: object) -> int | None:
    """Return one valid TCP/UDP port, or None for missing/invalid input."""
    ports = {port for port in _normalized_values(value, integer=True) if 0 < port <= 65535}
    return min(ports) if ports else None


def _normalized_services(value: object) -> set[str]:
    aliases = {
        "mqtt_websocket": "mqtt-ws", "mqtt-websocket": "mqtt-ws",
        "mqttws": "mqtt-ws", "websocket": "mqtt-ws", "ws": "mqtt-ws",
    }
    return {aliases.get(item, item) for item in _normalized_values(value)}


def _normalized_endpoints(value: object) -> set[str]:
    normalized: set[str] = set()
    for item in _normalized_values(value):
        path = item.split("?", 1)[0].split("#", 1)[0]
        if "://" in path:
            pieces = path.split("/", 3)
            path = "/" + pieces[3] if len(pieces) == 4 else "/"
        if len(path) > 1:
            path = path.rstrip("/")
        normalized.add(path or "/")
    return normalized


def _strict_v3_match(gt_vuln: dict, finding: dict) -> tuple[str, float, bool]:
    """Return (method, credit, structural_match), or an empty non-match.

    Conflicting explicit structure fails closed. Missing structure receives
    partial credit, while a non-primary but explicitly accepted semantic type
    receives categorical credit. No broad global category table is consulted.
    """
    if finding.get("device_ip", "") != gt_vuln.get("ip", ""):
        return "", 0.0, False

    contract = derive_matching_contract(gt_vuln)
    gt_cve = str(gt_vuln.get("cve") or "").upper()
    if gt_cve:
        finding_cves = {
            str(value).upper() for value in (finding.get("cve_ids") or [])
        }
        finding_products = _normalized_values(
            finding.get("products", finding.get("product"))
        )
        expected_products = set(contract["products"])
        finding_versions = _normalized_values(
            finding.get("versions", finding.get("version"))
        )
        expected_versions = {value.casefold() for value in contract.get("versions", [])}
        claim_text = " ".join(
            str(finding.get(field, "")) for field in ("details", "evidence")
        ).casefold()
        product_observed = (
            not expected_products
            or bool(finding_products & expected_products)
            or any(product in claim_text for product in expected_products)
        )
        version_observed = (
            not expected_versions
            or bool(finding_versions & expected_versions)
            or any(version in claim_text for version in expected_versions)
        )
        if (
            gt_cve not in finding_cves
            or not cve_is_allowed(gt_cve, contract["products"], contract.get("versions"))
            or not product_observed
            or not version_observed
        ):
            return "", 0.0, False
        if finding_products and expected_products and not finding_products & expected_products:
            return "", 0.0, False
        return "cve", 1.0, True

    accepted_types = contract["accepted_types"]
    finding_type = canonicalize(str(finding.get("type", "")))
    if finding_type not in accepted_types:
        return "", 0.0, False
    type_credit = 1.0 if accepted_types and finding_type == accepted_types[0] else 0.5

    constraints = {
        "service": _normalized_services(contract["services"]),
        "port": set(contract["ports"]),
        "protocol": set(contract["protocols"]),
        "endpoint": _normalized_endpoints(contract["endpoints"]),
        "product": set(contract["products"]),
    }
    observed = {
        "service": _normalized_services(finding.get("services", finding.get("service"))),
        "port": _normalized_values(finding.get("ports", finding.get("port")), integer=True),
        "protocol": _normalized_values(finding.get("protocols", finding.get("protocol"))),
        "endpoint": _normalized_endpoints(finding.get("endpoints") or finding.get("endpoint")),
        "product": _normalized_values(finding.get("products", finding.get("product"))),
    }

    declared = 0
    matched = 0
    for name, expected in constraints.items():
        if not expected:
            continue
        declared += 1
        actual = observed[name]
        if actual and not actual & expected:
            return "", 0.0, False
        if actual & expected:
            matched += 1

    structural_match = declared > 0 and matched == declared
    structural_ratio = matched / declared if declared else 1.0
    if type_credit < 1.0:
        return "explicit-category", 0.5 + 0.25 * structural_ratio, structural_match
    if structural_match:
        return "exact-structural", 1.0, True
    # Reward partial structure continuously instead of treating 0/5 like 4/5.
    return "exact-type", 0.75 + 0.25 * structural_ratio, False


def match_vuln(
    gt_vuln: dict,
    llm_findings: list[dict],
    policy: str | EvaluationPolicy = STRICT_V2.name,
) -> tuple[dict | None, str]:
    """Try to match a ground truth vuln to an LLM finding. Returns (finding, method)."""
    resolved = resolve_policy(policy)
    if resolved.use_explicit_contracts:
        best: tuple[dict | None, str, float] = (None, "", 0.0)
        for finding in llm_findings:
            method, credit, _ = _strict_v3_match(gt_vuln, finding)
            if credit >= resolved.min_match_credit and credit > best[2]:
                best = (finding, method, credit)
        return best[0], best[1]
    f = _match_by_cve(
        gt_vuln,
        llm_findings,
        require_same_ip=resolved.require_cve_same_ip,
    )
    if f:
        return f, "cve"

    # In strict mode a GT entry carrying a CVE must be identified by that CVE;
    # a generic type on the same host is insufficient.
    if resolved.require_cve_same_ip and gt_vuln.get("cve"):
        return None, ""

    f = _match_by_ip_and_type(gt_vuln, llm_findings)
    if f:
        return f, "ip+type"
    if resolved.allow_loose_match:
        f = _match_by_ip_and_service(gt_vuln, llm_findings)
        if f:
            return f, "ip+category"
    return None, ""


# ── Multi-Hop Reach (MHR) ──────────────────────────────────────────────────────

def compute_mhr(matches: list[dict], k: int) -> float | None:
    """Multi-Hop Reach @ depth k.

    MHR_k = | TP at hop_depth >= k | / | GT at hop_depth >= k |

    Returns None when no GT entry has hop_depth >= k (the metric is undefined for
    that scenario — e.g. a flat topology has MHR_1 = MHR_2 = MHR_3 = None).

    Convention: hop_depth=0 is directly reachable from the entry point. MHR_1 is
    therefore not raw recall; raw recall is reported separately. MHR_1+ measures
    findings that require at least one pivot or zone transition.

    `matches` is the result.matches list (asdict'd MatchResult), each entry has
    keys 'matched' (bool) and 'gt_hop_depth' (int).

    The interpretation: how good is the system at finding vulnerabilities that
    require crossing at least k network segments from the attacker's entry point?
    Systems that do not establish new vantage points are expected to score near
    zero on MHR_1+ by construction. Network-native pipelines with a lateral
    movement phase should score significantly higher.
    """
    gt_at_k = [m for m in matches if int(m.get("gt_hop_depth", 0)) >= k]
    if not gt_at_k:
        return None
    tp_at_k = sum(1 for m in gt_at_k if m.get("matched"))
    return round(tp_at_k / len(gt_at_k), 3)


def _compute_mhr_credit(matches: list[dict], k: int, *, verified: bool = False) -> float | None:
    """Continuous match credit, or fully verified reach, at depth >= k."""
    eligible = [match for match in matches if int(match.get("gt_hop_depth", 0)) >= k]
    if not eligible:
        return None
    if verified:
        value = sum(
            bool(match.get("matched")) and float(match.get("verification_credit", 0.0)) >= 1.0
            for match in eligible
        ) / len(eligible)
    else:
        value = sum(float(match.get("match_credit", 0.0)) for match in eligible) / len(eligible)
    return round(value, 3)


def _depth_histograms(matches: list[dict]) -> tuple[dict, dict]:
    """Return (gt_at_depth, tp_at_depth) histograms keyed by hop_depth value.

    Useful for debugging and for the §7 paper table — readers want to see
    how many GT entries exist at each depth, not just the cumulative MHR.
    """
    gt_hist: dict[int, int] = {}
    tp_hist: dict[int, int] = {}
    for m in matches:
        d = int(m.get("gt_hop_depth", 0))
        gt_hist[d] = gt_hist.get(d, 0) + 1
        if m.get("matched"):
            tp_hist[d] = tp_hist.get(d, 0) + 1
    return gt_hist, tp_hist


# ── Evaluator ─────────────────────────────────────────────────────────────────

# Phase 4 verdicts are resolved per Phase 3 finding.  A conclusive negative test
# is not equivalent to an infrastructure/tool error, and neither is equivalent
# to a finding that Phase 4 never tested.
_FAILED_PHASE4_STATUSES: frozenset[str] = frozenset({"FAILED", "NOT_EXPLOITABLE"})
_ERROR_PHASE4_STATUSES: frozenset[str] = frozenset({"ERROR"})
_EXPLOITED_PHASE4_STATUSES: frozenset[str] = frozenset({"CONFIRMED", "EXPLOITED", "COMPROMISED"})


def _run_metric_contract_status(
    run_dir: Path,
) -> tuple[str | None, str | None, bool, str | None]:
    """Return the run contract versions and evidence-metric compatibility.

    Missing, untrusted, or stale metadata fails closed so a modern evaluator
    cannot silently assign evidence-aware scores to legacy artifacts.
    """
    path = run_dir / "run_meta.json"
    if path.is_symlink():
        return None, None, False, "run_meta.json must not be a symlink"
    if not path.is_file():
        return None, None, False, "run_meta.json is missing"
    try:
        metadata = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None, None, False, "run_meta.json is unreadable"
    if not isinstance(metadata, dict):
        return None, None, False, "run_meta.json is not an object"

    metric_version = metadata.get("metric_contract_version")
    evidence_version = metadata.get("evidence_contract_version")
    metric_version = str(metric_version) if metric_version not in (None, "") else None
    evidence_version = str(evidence_version) if evidence_version not in (None, "") else None
    if metric_version != METRIC_CONTRACT_VERSION:
        return (
            metric_version,
            evidence_version,
            False,
            f"metric contract {metric_version or 'legacy'} != {METRIC_CONTRACT_VERSION}",
        )
    if evidence_version != EVIDENCE_CONTRACT_VERSION:
        return (
            metric_version,
            evidence_version,
            False,
            f"evidence contract {evidence_version or 'legacy'} != {EVIDENCE_CONTRACT_VERSION}",
        )
    return metric_version, evidence_version, True, None


def _load_tool_call_records(run_dir: Path) -> tuple[list[dict], bool]:
    """Load valid tool-call records and report whether a provenance log exists.

    Malformed lines are ignored instead of making the whole benchmark run
    unevaluable. A present but empty log is still available provenance: it
    records that no tool call can support a finding.
    """
    path = run_dir / "tool_calls.jsonl"
    if not path.is_file():
        return [], False
    records: list[dict] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return [], False
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict) and isinstance(record.get("tool"), str):
            evidence_ref = record.get("evidence_ref")
            if not isinstance(evidence_ref, str) or not evidence_ref.strip():
                evidence_ref = f"legacy-line-{line_number}"
            record = dict(record)
            record["_evidence_ref"] = evidence_ref.strip()[:128]
            records.append(record)
    return records, True


def _contains_structural_value(value: object, expected: str, *, numeric: bool = False) -> bool:
    """Find an exact structural value inside nested tool arguments."""
    if isinstance(value, dict):
        return any(_contains_structural_value(item, expected, numeric=numeric) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(_contains_structural_value(item, expected, numeric=numeric) for item in value)
    if numeric and isinstance(value, int) and not isinstance(value, bool):
        return value == int(expected)
    if not isinstance(value, str):
        return False
    if value.strip() == expected:
        return True
    boundary = r"(?<!\d)" if numeric else r"(?<![0-9A-Za-z])"
    end = r"(?!\d)" if numeric else r"(?![0-9A-Za-z])"
    return re.search(boundary + re.escape(expected) + end, value) is not None


def _record_implied_ports(record: dict) -> set[int]:
    """Extract explicit ports and safe protocol defaults from tool arguments."""
    args = record.get("args") or {}
    ports = set(_normalized_values(
        args.get("port") if isinstance(args, dict) else None, integer=True,
    ))
    if isinstance(args, dict):
        raw_ports = args.get("ports")
        if isinstance(raw_ports, (str, int)) and not isinstance(raw_ports, bool):
            ports.update(
                int(value) for value in re.findall(r"\d{1,5}", str(raw_ports))
                if 0 < int(value) <= 65535
            )
    text = json.dumps(args, ensure_ascii=False, default=str).casefold()
    ports.update(int(value) for value in re.findall(r":(\d{1,5})/", text))
    ports.update(int(value) for value in re.findall(r"(?:^|\s)-p\s*(\d{1,5})\b", text))
    if "http://" in text:
        ports.add(80)
    if "https://" in text:
        ports.add(443)
    if "ftp://" in text:
        ports.add(21)
    defaults = {
        "ssh_login": 22, "ssh_exec": 22, "ssh_audit": 22,
        "mqtt_listen": 1883, "mysql_query": 3306, "redis_cmd": 6379,
        "modbus_scan": 502, "telnet_connect": 23,
    }
    default = defaults.get(str(record.get("tool", "")).strip())
    if default is not None:
        ports.add(default)
    return {port for port in ports if 0 < port <= 65535}


def _record_implied_endpoints(record: dict) -> set[str]:
    """Extract exact URL paths or explicit endpoint arguments from a tool call."""
    endpoints: set[str] = set()

    def visit(value: object, key: str = "") -> None:
        if isinstance(value, dict):
            for child_key, child in value.items():
                visit(child, str(child_key).casefold())
            return
        if isinstance(value, (list, tuple, set)):
            for child in value:
                visit(child, key)
            return
        if not isinstance(value, str):
            return
        stripped = value.strip()
        if key in {"endpoint", "path", "uri"}:
            endpoints.update(_normalized_endpoints(stripped))
        for url in re.findall(r"https?://[^\s'\"]+", stripped):
            try:
                parsed = urlsplit(url.rstrip(".,)"))
            except ValueError:
                continue
            endpoints.update(_normalized_endpoints(parsed.path or "/"))

    visit(record.get("args") or {})
    explicit = record.get("endpoint")
    if explicit not in (None, ""):
        endpoints.update(_normalized_endpoints(explicit))
    return endpoints


def _canonical_tool_name(value: object) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "_", str(value).strip().casefold()).strip("_")
    aliases = {
        "nmap": "nmap_scan", "nmap_scan_phase_3": "nmap_scan",
        "nmap_scan_phase_3_evidence": "nmap_scan", "mysql_client": "mysql_query",
        "mysql": "mysql_query", "curl": "http_get",
    }
    return aliases.get(normalized, normalized)


def _finding_tool_names(finding: dict) -> set[str]:
    """Return exact tool names from the v3 list or conservative legacy strings."""
    names = {
        _canonical_tool_name(value)
        for value in (finding.get("tools_used") or [])
        if str(value).strip()
    }
    legacy = str(finding.get("tool_used", "")).strip()
    for segment in re.split(r"\s*(?:,|\+|/|;)\s*", legacy):
        segment = re.sub(r"\s*\(.*$", "", segment).strip()
        if not segment:
            continue
        canonical = _canonical_tool_name(segment)
        names.add(canonical)
        # Historical prose sometimes prefixes the exact tool with context.
        for known in (
            "nmap_scan", "nmap_discovery", "python_exec", "tcp_send", "udp_send",
            "http_get", "http_request", "curl_headers", "ssh_login", "ssh_exec",
            "ssh_audit", "mqtt_listen", "mysql_query", "ftp_list", "redis_cmd",
            "telnet_connect", "modbus_scan", "try_credential", "mtls_request",
        ):
            if re.search(rf"(?<![a-z0-9]){re.escape(known)}(?![a-z0-9])", canonical):
                names.add(known)
    return {name for name in names if name and name != "none"}


def _tool_call_matches_finding(finding: dict, record: dict) -> bool:
    """Match one call to one claim using explicit refs and structural context."""
    target_ip = str(finding.get("device_ip", "")).strip()
    record_tool = _canonical_tool_name(record.get("tool", ""))
    if not record_tool or record_tool not in _finding_tool_names(finding):
        return False
    declared_refs = {
        str(value).strip()
        for value in (finding.get("evidence_refs") or [])
        if str(value).strip()
    }
    record_ref = str(record.get("_evidence_ref", "")).strip()
    if declared_refs and record_ref not in declared_refs:
        return False

    finding_id = str(finding.get("id", "")).strip()
    record_finding_id = str(record.get("vuln_id", "")).strip()
    if record_finding_id and record_finding_id != finding_id:
        return False

    searchable = {"args": record.get("args"), "result": _tool_result_data(record)}
    if target_ip and not (
        str(record.get("device_ip", "")).strip() == target_ip
        or _contains_structural_value(searchable, target_ip)
    ):
        return False

    port = finding.get("port")
    if port not in (None, ""):
        record_port = record.get("port")
        if record_port not in (None, ""):
            try:
                if int(record_port) != int(port):
                    return False
            except (TypeError, ValueError):
                return False
        elif int(port) not in _record_implied_ports(record):
            return False

    endpoint = next(iter(_normalized_endpoints(finding.get("endpoint"))), "")
    if endpoint and endpoint != "/":
        record_endpoint = next(iter(_normalized_endpoints(record.get("endpoint"))), "")
        if record_endpoint:
            if record_endpoint != endpoint:
                return False
        elif endpoint not in _record_implied_endpoints(record):
            return False
    return True


def _assign_evidence_refs(findings: list[dict], tool_calls: list[dict]) -> int:
    """Assign each tool call to at most one finding; reject ambiguous reuse."""
    assigned: dict[int, list[str]] = {index: [] for index in range(len(findings))}
    ambiguous = 0
    for record in tool_calls:
        candidates = [
            index for index, finding in enumerate(findings)
            if _tool_call_matches_finding(finding, record)
        ]
        if len(candidates) == 1:
            ref = str(record.get("_evidence_ref", "")).strip()
            if ref:
                assigned[candidates[0]].append(ref)
        elif len(candidates) > 1:
            ambiguous += 1
    for index, finding in enumerate(findings):
        finding["_resolved_evidence_refs"] = list(dict.fromkeys(assigned[index]))
    return ambiguous


def _matching_tool_calls(finding: dict, tool_calls: list[dict]) -> list[dict]:
    """Return only calls assigned unambiguously to this finding."""
    if "_resolved_evidence_refs" in finding:
        refs = set(finding["_resolved_evidence_refs"])
        return [record for record in tool_calls if record.get("_evidence_ref") in refs]
    return [record for record in tool_calls if _tool_call_matches_finding(finding, record)]

def _has_tool_provenance(finding: dict, tool_calls: list[dict]) -> bool:
    """Return whether a finding cites a tool call made against the same target.

    Matching is deliberately strict and deterministic: the declared tool name
    must exactly equal a logged tool name, and a finding with a target IP must
    have that IP in the logged arguments or result. This measures traceability,
    not semantic correctness of the free-text evidence excerpt.
    """
    return bool(_matching_tool_calls(finding, tool_calls))


def _derive_evidence_level(test: dict) -> int:
    """Derive evidence strength from validated fields, never a model-provided integer."""
    status = str(test.get("status", "")).upper()
    extracted = test.get("data_extracted")
    has_extracted_data = isinstance(extracted, list) and bool(extracted)
    has_execution_trace = bool(_finding_tool_names(test)) and bool(
        str(test.get("evidence", "")).strip()
    )
    if status in _EXPLOITED_PHASE4_STATUSES and has_extracted_data:
        return 3
    if status in _EXPLOITED_PHASE4_STATUSES and has_execution_trace:
        return 2
    return 1


def _coerce_evidence_level(finding: dict) -> int:
    """Read an evidence level from legacy findings without trusting its type."""
    try:
        return int(finding.get("evidence_level", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _tool_result_data(record: dict) -> object:
    """Parse a JSON tool result when possible, preserving opaque text."""
    raw = record.get("result")
    if not isinstance(raw, str):
        return raw
    stripped = raw.strip()
    if not stripped:
        return ""
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return stripped


def _semantic_output_supports_finding(tool: str, result: dict, finding: dict | None) -> bool:
    """Interpret direct proof using each exploitation tool's output contract."""
    tool = _canonical_tool_name(tool)
    stdout = str(result.get("stdout", ""))
    stderr = str(result.get("stderr", ""))
    body = str(result.get("body", ""))
    received = str(result.get("received_ascii", ""))
    headers = result.get("headers", "")
    if isinstance(headers, dict):
        headers = "\n".join(f"{key}: {value}" for key, value in headers.items())
    text = "\n".join((
        stdout, stderr, body, received, str(headers),
        str(result.get("interpretation", "")),
    )).casefold()
    return_code = result.get("return_code")
    has_return_code = isinstance(return_code, int) and not isinstance(return_code, bool)

    if tool == "mqtt_listen":
        auth_failure = any(marker in text for marker in (
            "connection refused", "permission denied", "access denied", "noauth",
            "authentication required", "unauthorized",
        ))
        return (
            not auth_failure
            and has_return_code
            and return_code in {0, 27}
            and bool(stdout.strip())
        )

    if any(marker in text for marker in (
        "connection refused", "permission denied", "access denied", "noauth",
        "authentication required", "unauthorized", "timed out", "timeout",
        "[cache] only duplicate",
    )):
        return False
    if has_return_code and return_code != 0:
        return False
    if tool in {"ssh_login", "ssh_exec"}:
        return has_return_code and bool(re.search(
            r"\buid=\d+|\bgid=\d+|__ok__", stdout, re.IGNORECASE,
        ))
    if tool == "redis_cmd":
        return has_return_code and bool(stdout.strip()) and "error" not in text
    if tool == "mysql_query":
        return has_return_code and bool(stdout.strip()) and "denied" not in text and "error" not in text
    if tool == "ftp_list":
        return has_return_code and bool(stdout.strip()) and "failed" not in text
    if tool == "telnet_connect":
        return has_return_code and bool(stdout.strip())
    if tool == "ssh_audit":
        return has_return_code and any(
            marker in text for marker in ("[fail]", "[warn]", "cve-", "terrapin")
        )
    if tool in {"modbus_scan", "nmap_scan", "nmap_discovery"}:
        if not has_return_code or not text.strip():
            return False
        finding_type = canonicalize(str((finding or {}).get("type", "")))
        if tool == "modbus_scan":
            return "502/tcp" in text and "open" in text
        expected_port = _normalize_port((finding or {}).get("port"))
        open_port = bool(
            expected_port
            and re.search(rf"\b{expected_port}/(?:tcp|udp)\s+open\b", text)
        )
        if finding_type in {"no_auth", "insecure_protocol", "info_disclosure"}:
            return open_port
        return open_port and any(marker in text for marker in (
            "vulnerable", "vulners", "cve-", "anonymous login allowed",
            "authentication disabled", "default credential",
        ))
    if tool in {"tcp_send", "udp_send"}:
        received_bytes = result.get("received_bytes")
        return (
            isinstance(received_bytes, int)
            and not isinstance(received_bytes, bool)
            and received_bytes > 0
            and bool(received.strip() or str(result.get("received_hex", "")).strip())
        )
    if tool == "python_exec":
        if not has_return_code or not stdout.strip():
            return False
        extracted = (finding or {}).get("data_extracted") or []
        if extracted and any(
            str(value).casefold() in text for value in extracted if str(value).strip()
        ):
            return True
        finding_type = canonicalize(str((finding or {}).get("type", "")))
        markers = {
            "code_injection": ("uid=", "gid=", "command output", "__ok__"),
            "data_exposure": ("password", "api_key", "secret", "private key"),
            "privilege_escalation": ("uid=0", "euid=0", "root"),
        }.get(finding_type, ())
        return any(marker in text for marker in markers)
    if tool in {"http_get", "curl_headers", "http_request", "mtls_request"}:
        status_code = result.get("status_code")
        if isinstance(status_code, int) and status_code in {401, 403, 404}:
            return False
        if re.search(r"http/\S+\s+(401|403|404)\b", text):
            return False
        if not text.strip() or (
            not has_return_code and not isinstance(status_code, int)
        ):
            return False
        extracted = (finding or {}).get("data_extracted") or []
        if extracted and any(str(value).casefold() in text for value in extracted if str(value).strip()):
            return True
        finding_type = canonicalize(str((finding or {}).get("type", "")))
        markers = {
            "directory_listing": ("index of /", "directory listing"),
            "data_exposure": ("password", "passwd", "api_key", "secret", "private key", "credential"),
            "code_injection": ("uid=", "gid=", "command output"),
            "missing_header": ("http/", "server:"),
            "info_disclosure": ("server:", "version", "$sys"),
            "no_auth": ("admin", "device", "dashboard", "status"),
        }.get(finding_type, ())
        return any(marker in text for marker in markers)
    return False


def _tool_call_outcome(record: dict, finding: dict | None = None) -> bool | None:
    """Return a conservative, tool-specific exploitation success verdict."""
    result = _tool_result_data(record)
    if isinstance(result, dict):
        success = result.get("success")
        if isinstance(success, bool):
            return success
        ok = result.get("ok")
        if isinstance(ok, bool):
            return ok
        status = result.get("status")
        if isinstance(status, str):
            normalized = status.strip().lower()
            if normalized in {"ok", "success", "succeeded", "confirmed", "exploited"}:
                return True
            if normalized in {"error", "failed", "failure", "timeout"}:
                return False
        if result.get("error"):
            return False
        tool = str(record.get("tool", "")).strip()
        return_code = result.get("return_code")
        if isinstance(return_code, int) and not isinstance(return_code, bool):
            if return_code not in {0, 27}:
                return False
        supported_tools = {
            "mqtt_listen", "ssh_login", "ssh_exec", "redis_cmd", "mysql_query",
            "ftp_list", "telnet_connect", "ssh_audit", "modbus_scan",
            "nmap_scan", "nmap_discovery", "http_get", "curl_headers",
            "http_request", "mtls_request", "tcp_send", "udp_send", "python_exec",
        }
        if _canonical_tool_name(tool) in supported_tools:
            return _semantic_output_supports_finding(tool, result, finding)
        return None
    if isinstance(result, str):
        normalized = result.strip().lower()
        if normalized in {"ok", "success", "succeeded", "confirmed", "exploited"}:
            return True
        if normalized in {"error", "failed", "failure", "timeout"}:
            return False
    return None

def _tool_result_text(records: list[dict]) -> str:
    """Return normalized result text for literal extracted-data verification."""
    fragments: list[str] = []

    def collect(value: object) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                fragments.append(str(key))
                collect(item)
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                collect(item)
            return
        fragments.append(str(value))

    for record in records:
        result = _tool_result_data(record)
        # Keep the serialized form for compatibility and add scalar leaves
        # without JSON escaping so embedded JSON text remains searchable.
        fragments.append(json.dumps(result, ensure_ascii=False, default=str))
        collect(result)
    return "\n".join(fragments).casefold()


def _claim(
    kind: str,
    value: object,
    verdict: str,
    *,
    evidence_refs: list[str] | None = None,
    reason: str,
) -> dict:
    return {
        "kind": kind,
        "value": value,
        "verdict": verdict,
        "evidence_refs": evidence_refs or [],
        "reason": reason,
    }


def _assess_evidence_claims(
    finding: dict,
    *,
    finding_index: int,
    outcome: str,
    matched_gt: dict | None,
    match_method: str,
    tool_calls: list[dict],
) -> dict:
    """Assess structured, checkable finding claims without an LLM judge.

    Free-text details and remediation are intentionally excluded because they
    cannot be decomposed reliably without introducing another semantic judge.
    """
    records = _matching_tool_calls(finding, tool_calls)
    tool_refs = [str(record.get("_evidence_ref", "")) for record in records]
    tool_refs = [ref for ref in tool_refs if ref]
    gt_refs = [f"gt:{matched_gt.get('id')}"] if matched_gt and matched_gt.get("id") else []
    claims: list[dict] = []

    target_ip = str(finding.get("device_ip", "")).strip()
    if target_ip:
        claims.append(_claim(
            "target", target_ip, "supported" if records else "unverifiable",
            evidence_refs=tool_refs,
            reason=(
                "matching tool call targets this address"
                if records else "no matching tool call targets this address"
            ),
        ))

    vuln_type = str(finding.get("type", "")).strip()
    if vuln_type:
        if outcome == "true_positive" and match_method in {
            "cve", "ip+type", "exact-structural", "exact-type",
            "explicit-category",
        }:
            verdict, refs, reason = "supported", gt_refs, "finding matches ground truth"
        elif outcome == "true_positive":
            verdict, refs, reason = (
                "unverifiable", gt_refs, "loose ground-truth match is insufficient support"
            )
        elif outcome == "false_positive":
            verdict, refs, reason = (
                "unverifiable", [], "unmatched ground truth provides no claim support"
            )
        else:
            verdict, refs, reason = "unverifiable", [], "bonus finding is outside ground truth"
        claims.append(_claim(
            "vulnerability", vuln_type, verdict,
            evidence_refs=refs, reason=reason,
        ))

    status = str(finding.get("status", "")).upper()
    if status in _EXPLOITED_PHASE4_STATUSES:
        outcomes = [_tool_call_outcome(record, finding) for record in records]
        if any(value is True for value in outcomes):
            verdict, reason = "supported", "matching tool result reports success"
        elif outcomes and all(value is False for value in outcomes):
            verdict, reason = "contradicted", "all matching tool results report failure"
        else:
            verdict, reason = "unverifiable", "matching tool result has no generic success signal"
        claims.append(_claim(
            "exploitation", status, verdict,
            evidence_refs=tool_refs, reason=reason,
        ))

    result_text = _tool_result_text(records)
    extracted = finding.get("data_extracted")
    if isinstance(extracted, list):
        for item in extracted:
            value = item if isinstance(item, (str, int, float, bool)) else json.dumps(item, ensure_ascii=False, default=str)
            needle = str(value).strip().casefold()
            supported = bool(needle) and needle in result_text
            claims.append(_claim(
                "data_extracted", value,
                "supported" if supported else "unverifiable",
                evidence_refs=tool_refs if supported else [],
                reason=(
                    "extracted value appears in matching tool output"
                    if supported else "extracted value is absent from matching tool output"
                ),
            ))

    gt_cve = str(matched_gt.get("cve", "")).upper() if matched_gt else ""
    for cve in finding.get("cve_ids", []) or []:
        normalized_cve = str(cve).upper()
        in_tool_output = normalized_cve.casefold() in result_text
        if normalized_cve and (normalized_cve == gt_cve or in_tool_output):
            verdict = "supported"
            refs = gt_refs if normalized_cve == gt_cve else tool_refs
            reason = "CVE matches ground truth or tool output"
        elif matched_gt and gt_cve:
            verdict, refs, reason = "contradicted", gt_refs, "CVE differs from matched ground truth"
        else:
            verdict, refs, reason = "unverifiable", [], "CVE has no supporting reference"
        claims.append(_claim(
            "cve", normalized_cve, verdict,
            evidence_refs=refs, reason=reason,
        ))

    return {
        "finding_index": finding_index,
        "finding_id": finding.get("id", ""),
        "outcome": outcome,
        "claims": claims,
    }


def _phase3_has_direct_evidence(finding: dict | None) -> bool:
    """Return whether Phase 3 declares direct evidence under its artifact contract.

    Phase 3 prompts reserve ``exploitation_status=confirmed`` for raw tool
    output that directly demonstrates the vulnerability.  Requiring a non-empty
    evidence excerpt avoids treating a bare status label as proof.
    """
    if not finding:
        return False
    return (
        str(finding.get("exploitation_status", "")).strip().lower() == "confirmed"
        and bool(str(finding.get("evidence", "")).strip())
    )


def _phase3_detection_finding(finding: dict, verification_status: str) -> dict:
    """Keep a Phase 3 finding as detection-level, without exploitation credit."""
    return {
        "id": finding.get("id", ""),
        "device_id": finding.get("device_id", ""),
        "device_ip": finding.get("device_ip", ""),
        "type": finding.get("type", ""),
        "severity": finding.get("severity", ""),
        "service": finding.get("service", ""),
        "port": finding.get("port"),
        "protocol": finding.get("protocol", ""),
        "endpoint": finding.get("endpoint", ""),
        "endpoints": finding.get("endpoints", []),
        "product": finding.get("product", ""),
        "version": finding.get("version", ""),
        "details": finding.get("details", ""),
        "evidence": finding.get("evidence", ""),
        "evidence_level": 1,
        "tool_used": "",
        "tools_used": [],
        "evidence_refs": [],
        "data_extracted": [],
        "traceable_evidence": False,
        "status": "DETECTED",
        "phase4_verification": verification_status,
        "remediation": finding.get("remediation", ""),
        "cve_ids": _sanitize_cve_ids(finding.get("cve_ids", [])),
    }


def _load_llm_findings(run_dir: Path) -> list[dict]:
    """Return findings after resolving Phase 4 verdicts individually.

    CONFIRMED enriches the corresponding Phase 3 finding. FAILED refutes it,
    unless Phase 3 already carries direct evidence. ERROR and missing tests are
    indeterminate and therefore retain the Phase 3 finding at detection level.
    Falls back entirely to Phase 3 only when no Phase 4 artifact exists.
    """
    exploit_file = run_dir / "04_exploitation.json"
    vuln_file = run_dir / "03_vuln_analysis.json"
    # Provenance is assigned globally after all findings are materialized.

    p3_findings: list[dict] = []
    p3_indices_by_id: dict[str, list[int]] = {}
    if vuln_file.exists():
        p3_findings = json.loads(vuln_file.read_text()).get("vulnerabilities", [])
        for index, finding in enumerate(p3_findings):
            p3_indices_by_id.setdefault(str(finding.get("id", "")), []).append(index)

    if exploit_file.exists():
        raw = json.loads(exploit_file.read_text())
        # Accept both "tests" (current pipeline format) and "vulnerabilities"
        # (legacy MiniMax format where Phase 4 reused Phase 3 structure).
        is_legacy_findings = "tests" not in raw and "vulnerabilities" in raw
        test_list = (
            raw.get("vulnerabilities", [])
            if is_legacy_findings
            else raw.get("tests", [])
        )
        findings = []
        tested_p3_indices: set[int] = set()
        for t in test_list:
            vuln_id = t.get("vuln_id") or t.get("id", "")
            available = p3_indices_by_id.get(str(vuln_id), [])
            p3_index = available.pop(0) if available else None
            p3 = p3_findings[p3_index] if p3_index is not None else None
            if p3_index is not None:
                tested_p3_indices.add(p3_index)
            vuln_type = t.get("vuln_type") or t.get("type", "")
            if not vuln_type and p3:
                vuln_type = p3.get("type", "")
            if vuln_type in NOISE_TYPES:
                continue
            status = str(t.get("status", "")).strip().upper()
            if status in _FAILED_PHASE4_STATUSES:
                if (
                    _phase3_has_direct_evidence(p3)
                    and p3.get("type", "") not in NOISE_TYPES
                ):
                    findings.append(_phase3_detection_finding(
                        p3, "conflicting_direct_phase3_evidence",
                    ))
                continue
            if status in _ERROR_PHASE4_STATUSES or (
                not is_legacy_findings and status not in _EXPLOITED_PHASE4_STATUSES
            ):
                if p3 and p3.get("type", "") not in NOISE_TYPES:
                    findings.append(_phase3_detection_finding(
                        p3, "error" if status in _ERROR_PHASE4_STATUSES else "unknown_status",
                    ))
                continue
            finding = {
                "id": vuln_id,
                "device_id": t.get("device_id") or (p3 or {}).get("device_id", ""),
                "device_ip": t.get("device_ip") or (p3 or {}).get("device_ip", ""),
                "type": vuln_type,
                "severity": t.get("severity") or (p3 or {}).get("severity", ""),
                "service": t.get("service") or (p3 or {}).get("service", ""),
                "port": t.get("port") if t.get("port") is not None else (p3 or {}).get("port"),
                "protocol": t.get("protocol") or (p3 or {}).get("protocol", ""),
                "endpoint": t.get("endpoint") or (p3 or {}).get("endpoint", ""),
                "endpoints": t.get("endpoints") or (p3 or {}).get("endpoints", []),
                "product": t.get("product") or (p3 or {}).get("product", ""),
                "version": t.get("version") or (p3 or {}).get("version", ""),
                "details": (
                    t.get("description") or t.get("details")
                    or (p3 or {}).get("details", "")
                ),
                "evidence": t.get("evidence", ""),
                "evidence_level": _derive_evidence_level(t),
                "tool_used": t.get("tool_used", ""),
                "tools_used": t.get("tools_used", []),
                "evidence_refs": t.get("evidence_refs", []),
                "data_extracted": t.get("data_extracted", []),
                "status": status,
                "phase4_verification": (
                    status.lower() if status else "legacy_finding"
                ),
                "remediation": t.get("remediation") or (p3 or {}).get("remediation", ""),
                "cve_ids": _sanitize_cve_ids(
                    t.get("cve_ids") or (p3 or {}).get("cve_ids", [])
                ),
            }
            finding["traceable_evidence"] = False
            findings.append(finding)
        # Phase 4 may deliberately omit config-only findings, or may terminate
        # before scheduling every candidate. Absence of a test is not negative
        # evidence, so retain those Phase 3 findings as unverified detections.
        for p3_index, p3 in enumerate(p3_findings):
            if p3_index not in tested_p3_indices and p3.get("type", "") not in NOISE_TYPES:
                findings.append(_phase3_detection_finding(p3, "not_tested"))

        return findings

    if vuln_file.exists():
        vulns = json.loads(vuln_file.read_text()).get("vulnerabilities", [])
        sanitized = []
        for v in vulns:
            if v.get("type", "") in NOISE_TYPES:
                continue
            v = dict(v)
            v["cve_ids"] = _sanitize_cve_ids(v.get("cve_ids", []))
            sanitized.append(v)
        return sanitized

    raise FileNotFoundError(
        f"Neither 04_exploitation.json nor 03_vuln_analysis.json found in {run_dir}"
    )


def evaluate(
    run_dir: Path,
    ground_truth_file: Path,
    policy: str | EvaluationPolicy = STRICT_V2.name,
) -> EvaluationResult:
    resolved_policy = resolve_policy(policy)

    # Load ground truth
    gt_data = yaml.safe_load(ground_truth_file.read_text())
    gt_vulns = gt_data.get("vulnerabilities", [])
    gt_controls = gt_data.get("controls", []) or []
    gt_attack_paths = gt_data.get("attack_paths", [])
    scenario_id = str(gt_data.get("scenario_id", "?"))
    if resolved_policy.use_explicit_contracts:
        contract_file = ground_truth_file.parent / "matching_contracts.yaml"
        if contract_file.is_file():
            try:
                contract_data = yaml.safe_load(contract_file.read_text(encoding="utf-8")) or {}
                if contract_data.get("schema_version") != "strict-v3.2":
                    raise ValueError(f"Unsupported strict-v3 contract schema: {contract_file}")
                expected_hash = str((contract_data.get("source_hashes", {}) or {}).get(scenario_id, ""))
                actual_hash = hashlib.sha256(ground_truth_file.read_bytes()).hexdigest()
                if not expected_hash or expected_hash != actual_hash:
                    raise ValueError(
                        f"Stale strict-v3 contract for S{scenario_id}; regenerate {contract_file}"
                    )
                scenario_contracts = (contract_data.get("scenarios", {}) or {}).get(scenario_id)
                if not isinstance(scenario_contracts, dict):
                    raise ValueError(f"Missing strict-v3 contracts for S{scenario_id}")
                gt_vulns = [
                    {
                        **scenario_contracts.get(str(vulnerability.get("id", "")), {}),
                        **vulnerability,
                    }
                    for vulnerability in gt_vulns
                ]
            except (OSError, UnicodeError, yaml.YAMLError, AttributeError):
                # The conservative legacy derivation remains available, but the
                # contract source is visible in match diagnostics/documentation.
                pass
    raw_weights = gt_data.get("scoring", {}).get(
        "weights", {"critical": 4, "high": 3, "medium": 2, "low": 1}
    )
    weights = {str(key).lower(): value for key, value in raw_weights.items()}
    bonus_types = set(gt_data.get("bonus_types", []))
    scoring_config = gt_data.get("scoring", {}) or {}
    bonus_allowance = int(scoring_config.get("max_bonus_findings", len(bonus_types)))
    bonus_allowance = max(0, bonus_allowance)
    raw_per_type_cap = scoring_config.get("max_bonus_findings_per_type", 1)
    per_type_caps = raw_per_type_cap if isinstance(raw_per_type_cap, dict) else {}
    default_per_type_cap = max(0, int(raw_per_type_cap)) if not isinstance(raw_per_type_cap, dict) else 1

    # Auto-compute max_weighted_score from actual vulnerabilities (authoritative).
    # The YAML field is kept for documentation but not trusted to avoid silent typos.
    max_score = sum(weights.get(gt.get("severity", "low").lower(), 1) for gt in gt_vulns)
    yaml_max = gt_data.get("scoring", {}).get("max_weighted_score", 0)
    if yaml_max > 0 and yaml_max != max_score:
        import warnings
        warnings.warn(
            f"S{scenario_id}: max_weighted_score in YAML ({yaml_max}) differs from "
            f"computed ({max_score}). Using computed value."
        )

    llm_findings = _load_llm_findings(run_dir)
    run_metric_version, run_evidence_version, evidence_compatible, compatibility_reason = (
        _run_metric_contract_status(run_dir)
    )
    phase4_artifact_available = (run_dir / "04_exploitation.json").is_file()
    tool_calls, provenance_log_available = _load_tool_call_records(run_dir)
    evidence_metrics_available = phase4_artifact_available and evidence_compatible
    evidence_provenance_available = provenance_log_available and evidence_compatible

    cost_file = run_dir / "cost_summary.json"
    cost_data: dict = {}
    if cost_file.exists():
        try:
            loaded = json.loads(cost_file.read_text())
            if isinstance(loaded, dict):
                cost_data = loaded
        except (OSError, UnicodeError, json.JSONDecodeError):
            cost_data = {}

    def _number(name: str) -> float | None:
        value = cost_data.get(name)
        return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None

    def _integer(name: str) -> int | None:
        value = cost_data.get(name)
        return int(value) if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None

    process_schema = _integer("metrics_schema_version")
    process_available = False
    total_cost_usd = _number("total_cost_usd")
    input_tokens = _integer("total_input_tokens")
    output_tokens = _integer("total_output_tokens")
    total_tokens = input_tokens + output_tokens if input_tokens is not None and output_tokens is not None else None
    total_turns = _integer("total_turns")
    total_tool_calls = _integer("total_tool_calls")
    ambiguous_evidence_refs = _assign_evidence_refs(llm_findings, tool_calls)
    for finding in llm_findings:
        finding["traceable_evidence"] = (
            _coerce_evidence_level(finding) >= 2
            and bool(finding.get("_resolved_evidence_refs"))
        )

    format_fallbacks = _integer("total_format_fallbacks")
    format_attempts = _integer("total_format_attempts")
    validation_failures = _integer("total_validation_failures")
    validation_attempts = _integer("total_validation_attempts")
    validation_successes = _integer("total_validation_successes")
    total_tool_errors = _integer("total_tool_errors")
    required_process_counts = (
        total_tool_calls, format_fallbacks, format_attempts, validation_failures,
        validation_attempts, validation_successes, total_tool_errors,
    )
    process_available = (
        process_schema == 2
        and all(value is not None for value in required_process_counts)
        and format_fallbacks <= format_attempts
        and validation_successes + validation_failures == validation_attempts
        and total_tool_errors <= total_tool_calls
    )

    result = EvaluationResult(
        scenario_id=scenario_id,
        run_dir=str(run_dir),
        ground_truth_file=str(ground_truth_file),
        scoring_policy=resolved_policy.name,
        run_metric_contract_version=run_metric_version,
        run_evidence_contract_version=run_evidence_version,
        evidence_contract_compatible=evidence_compatible,
        metrics_compatibility_reason=compatibility_reason,
        is_zero_gt=not gt_vulns,
        total_gt_vulns=len(gt_vulns),
        total_llm_findings=len(llm_findings),
        max_weighted_score=max_score,
        total_attack_paths=len(gt_attack_paths),
        evidence_metrics_available=evidence_metrics_available,
        evidence_provenance_available=evidence_provenance_available,
        ambiguous_evidence_refs=ambiguous_evidence_refs,
        process_metrics_schema_version=process_schema,
        process_metrics_available=process_available,
        total_cost_usd=total_cost_usd,
        cost_is_estimate=cost_data.get("cost_is_estimate") if isinstance(cost_data.get("cost_is_estimate"), bool) else None,
        total_tokens=total_tokens,
        total_turns=total_turns,
        total_tool_calls=total_tool_calls,
        format_fallbacks=format_fallbacks,
        format_attempts=format_attempts,
        validation_failures=validation_failures,
        validation_attempts=validation_attempts,
        validation_successes=validation_successes,
        total_tool_errors=total_tool_errors,
        bonus_allowance=bonus_allowance,
        negative_controls_total=0,
    )

    raw_cve_claims: dict[tuple[str, str], dict] = {}
    for artifact_name, collection_names in (
        ("03_vuln_analysis.json", ("vulnerabilities",)),
        ("04_exploitation.json", ("tests", "vulnerabilities")),
    ):
        artifact = run_dir / artifact_name
        if not artifact.is_file():
            continue
        try:
            payload = json.loads(artifact.read_text(encoding="utf-8"))
            entries = next(
                (payload.get(name, []) for name in collection_names if name in payload), []
            ) or []
            for entry in entries:
                finding_id = str(entry.get("vuln_id") or entry.get("id", ""))
                for cve in entry.get("cve_ids", []) or []:
                    raw_cve_claims[(finding_id, str(cve).upper())] = entry
        except (OSError, UnicodeError, json.JSONDecodeError, AttributeError):
            continue
    for (_finding_id, cve), entry in raw_cve_claims.items():
        if not _CVE_YEAR_RE.fullmatch(cve) or _cve_is_suspicious(cve):
            result.malformed_cve_claims += 1
            continue
        if cve not in OFFLINE_CVE_CATALOG:
            result.unknown_cve_claims += 1
            continue
        products = list(_normalized_values(entry.get("products", entry.get("product"))))
        versions = list(_normalized_values(entry.get("versions", entry.get("version"))))
        if (products or versions) and not cve_is_allowed(cve, products, versions):
            result.inapplicable_cve_claims += 1
    result.invalid_cve_claims = (
        result.malformed_cve_claims + result.inapplicable_cve_claims
    )

    # Completion measures conclusive verification of Phase-4-eligible Phase 3
    # candidates. ERROR, unknown and absent tests remain incomplete.
    p3_path = run_dir / "03_vuln_analysis.json"
    p4_path = run_dir / "04_exploitation.json"
    if p3_path.is_file() and p4_path.is_file():
        try:
            p3_raw = json.loads(p3_path.read_text(encoding="utf-8"))
            p4_raw = json.loads(p4_path.read_text(encoding="utf-8"))
            candidates = [
                finding for finding in (p3_raw.get("vulnerabilities", []) or [])
                if finding.get("type", "") not in NOISE_TYPES
                and not is_config_only(finding.get("type", ""))
            ]
            candidate_ids = [str(finding.get("id", "")) for finding in candidates]
            conclusive_statuses = _EXPLOITED_PHASE4_STATUSES | _FAILED_PHASE4_STATUSES
            conclusive_ids = [
                str(test.get("vuln_id") or test.get("id", ""))
                for test in (p4_raw.get("tests", []) or [])
                if str(test.get("status", "")).strip().upper() in conclusive_statuses
            ]
            remaining = Counter(candidate_ids)
            conclusive_count = 0
            for vuln_id in conclusive_ids:
                if remaining[vuln_id] > 0:
                    remaining[vuln_id] -= 1
                    conclusive_count += 1
            result.phase4_candidates = len(candidate_ids)
            result.phase4_conclusive = conclusive_count
            result.phase4_completion_rate = (
                round(result.phase4_conclusive / result.phase4_candidates, 3)
                if result.phase4_candidates else 1.0
            )
        except (OSError, UnicodeError, json.JSONDecodeError, AttributeError):
            result.phase4_completion_rate = None

    if result.evidence_metrics_available:
        result.findings_with_declared_evidence = sum(
            1 for finding in llm_findings
            if bool(str(finding.get("evidence", "")).strip())
        )
        result.findings_with_execution_evidence = sum(
            1 for finding in llm_findings
            if _coerce_evidence_level(finding) >= 2
        )
        if llm_findings:
            result.declared_evidence_coverage = round(
                result.findings_with_declared_evidence / len(llm_findings), 3
            )
            result.execution_evidence_coverage = round(
                result.findings_with_execution_evidence / len(llm_findings), 3
            )
        if result.evidence_provenance_available:
            result.findings_with_traceable_evidence = sum(
                1 for finding in llm_findings
                if finding.get("traceable_evidence") is True
            )
            if llm_findings:
                result.traceable_evidence_coverage = round(
                    result.findings_with_traceable_evidence / len(llm_findings), 3
                )

    match_method_by_finding: dict[int, str] = {}
    # Findings are identified by their list index, never by model-provided IDs.
    # IDs are frequently blank or duplicated and must not hide false positives.
    matched_llm_indices: set[int] = set()
    finding_outcomes: dict[int, str] = {}
    matched_gt_by_finding: dict[int, dict] = {}

    # Sort GT vulns by category specificity (narrow categories match first to avoid
    # broad categories like "misconfiguration" stealing narrow matches like "missing_header").
    def _category_specificity(gt_vuln: dict) -> int:
        category = gt_vuln.get("category", "")
        compatible = CATEGORY_TO_TYPE.get(category, set())
        # Fallback: check title-inferred type size (more specific titles first)
        inferred = _infer_type_from_title(gt_vuln.get("title", ""))
        if inferred and inferred not in compatible:
            return 0  # title-inferred types are highest priority, sort first
        return len(compatible) if compatible else 999

    sorted_gt = sorted(enumerate(gt_vulns), key=lambda pair: _category_specificity(pair[1]))
    matches_by_gt_index: dict[int, tuple[dict | None, str, int | None]] = {}

    # Solve matching globally instead of greedily consuming the first compatible
    # finding. This maximizes one-to-one match quality and removes dependence on
    # GT ordering when several findings share a target.
    graph = nx.Graph()
    method_weight = {
        "cve": 4000,
        "exact-structural": 3500,
        "exact-type": 2500,
        "explicit-category": 1500,
        "ip+type": 2000,
        "ip+category": 1000,
    }
    edge_methods: dict[tuple[int, int], str] = {}
    edge_credits: dict[tuple[int, int], float] = {}
    edge_structural: dict[tuple[int, int], bool] = {}
    for gt_index, gt in sorted_gt:
        graph.add_node(("gt", gt_index), bipartite=0)
        for finding_index, finding in enumerate(llm_findings):
            match, method = match_vuln(gt, [finding], policy=resolved_policy)
            if match is None:
                continue
            if resolved_policy.use_explicit_contracts:
                method, match_credit, structural_match = _strict_v3_match(gt, finding)
                if match_credit < resolved_policy.min_match_credit:
                    continue
            else:
                match_credit = 0.5 if method == "ip+category" else 1.0
                structural_match = False
            severity_bonus = 100 if (
                str(finding.get("severity", "")).lower()
                == str(gt.get("severity", "")).lower()
            ) else 0
            finding_type = str(finding.get("type", ""))
            bonus_penalty = 500 if (
                finding_type in bonus_types or canonicalize(finding_type) in bonus_types
            ) else 0
            graph.add_edge(
                ("gt", gt_index),
                ("finding", finding_index),
                weight=(
                    method_weight[method]
                    + int(match_credit * 1000)
                    + severity_bonus
                    - bonus_penalty
                ),
            )
            edge_methods[(gt_index, finding_index)] = method
            edge_credits[(gt_index, finding_index)] = match_credit
            edge_structural[(gt_index, finding_index)] = structural_match

    selected = nx.algorithms.matching.max_weight_matching(
        graph, maxcardinality=True, weight="weight"
    )
    for left, right in selected:
        if left[0] == "finding":
            left, right = right, left
        gt_index = int(left[1])
        finding_index = int(right[1])
        matched_llm_indices.add(finding_index)
        matches_by_gt_index[gt_index] = (
            llm_findings[finding_index],
            edge_methods[(gt_index, finding_index)],
            finding_index,
        )
    for gt_index, _gt in sorted_gt:
        matches_by_gt_index.setdefault(gt_index, (None, "", None))

    credited_tp = 0.0
    severity_adjusted_tp = 0.0
    quality_adjusted_tp = 0.0

    # Re-iterate in original order to preserve report output
    for gt_index, gt in enumerate(gt_vulns):
        match, method, _match_index = matches_by_gt_index[gt_index]
        severity = str(gt.get("severity", "low")).lower()
        weight = weights.get(severity, 1)

        mr = MatchResult(
            gt_id=gt["id"],
            gt_title=gt["title"],
            gt_device=gt.get("device", ""),
            gt_ip=gt.get("ip", ""),
            gt_severity=severity,
            matched=match is not None,
            gt_hop_depth=int(gt.get("hop_depth", 0)),
        )

        if match:
            finding_outcomes[_match_index] = "true_positive"
            matched_gt_by_finding[_match_index] = gt
            match_method_by_finding[_match_index] = method
            mr.llm_id = match.get("id", "")
            mr.llm_type = match.get("type", "")
            mr.llm_severity = match.get("severity", "")
            mr.match_method = method
            mr.match_credit = edge_credits[(gt_index, _match_index)]
            mr.structural_match = edge_structural[(gt_index, _match_index)]
            mr.phase4_verification = match.get("phase4_verification", "")
            mr.severity_match = (
                (match.get("severity") or "").lower() == severity.lower()
            )
            result.true_positives += 1
            credited_tp += mr.match_credit
            if not mr.severity_match:
                result.severity_mismatches += 1

            # Exploitation coverage requires both a derived execution level and
            # an explicitly successful linked tool result. Traceability alone
            # proves provenance, not successful exploitation.
            evidence_level = match.get("evidence_level", 0)
            try:
                evidence_level = int(evidence_level)
            except (TypeError, ValueError):
                evidence_level = 0
            matching_calls = _matching_tool_calls(match, tool_calls)
            verified_exploitation = (
                evidence_level >= 2
                and any(_tool_call_outcome(call, match) is True for call in matching_calls)
            )
            if verified_exploitation:
                result.tp_exploited += 1
                mr.verification_credit = 1.0
            else:
                result.tp_detected_only += 1
                # Declared/direct evidence receives limited credit, while an
                # untested/error-only detection receives only hypothesis credit.
                mr.verification_credit = (
                    0.5
                    if evidence_level >= 1 or bool(str(match.get("evidence", "")).strip())
                    else 0.25
                )
            if match.get("traceable_evidence") is True:
                result.traceable_true_positives += 1

            # Scoring penalties:
            #   ip+category (loose match)  → 0.5x  (structural ambiguity)
            #   severity mismatch          → 0.75x  (right vuln, wrong impact)
            #   both combined              → 0.5 * 0.75 = 0.375x
            gt_rank = SEVERITY_RANK.get(severity, 1)
            finding_rank = SEVERITY_RANK.get(
                str(match.get("severity", "low")).lower(), 1
            )
            severity_factor = max(0.25, 1.0 - 0.25 * abs(gt_rank - finding_rank))
            severity_adjusted_tp += mr.match_credit * severity_factor
            quality_adjusted_tp += (
                mr.match_credit * severity_factor * mr.verification_credit
            )
            score_weight = weight * mr.match_credit * severity_factor
            result.weighted_score += score_weight
        else:
            result.false_negatives += 1

        result.matches.append(asdict(mr))

    # Devices that have at least one matched GT finding — used to classify "bonus" findings.
    matched_device_ips: set[str] = {
        m["gt_ip"] for m in result.matches if m.get("matched") and m.get("gt_ip")
    }

    # Classify unmatched LLM findings: bonus (real but not in GT) vs false positive.
    accepted_bonus_counts: Counter[str] = Counter()
    accepted_bonus_signatures: set[tuple] = set()
    for finding_index, f in enumerate(llm_findings):
        if finding_index in matched_llm_indices:
            continue

        f_type = f.get("type", "")
        f_type_canon = canonicalize(f_type)
        f_ip = f.get("device_ip", "")
        is_bonus = False

        explicit_bonus = bool(
            bonus_types and (f_type in bonus_types or f_type_canon in bonus_types)
        )
        if explicit_bonus:
            if resolved_policy.require_traceable_bonus:
                signature = (
                    f_type_canon, f_ip, f.get("port"),
                    tuple(sorted(_normalized_endpoints(f.get("endpoint")))),
                )
                type_cap = max(0, int(per_type_caps.get(f_type_canon, default_per_type_cap)))
                if f.get("traceable_evidence") is not True:
                    result.bonus_untraceable += 1
                    result.bonus_overflow += 1
                elif signature in accepted_bonus_signatures:
                    result.bonus_duplicates += 1
                    result.bonus_overflow += 1
                elif result.bonus_findings >= bonus_allowance or accepted_bonus_counts[f_type_canon] >= type_cap:
                    result.bonus_cap_exceeded += 1
                    result.bonus_overflow += 1
                else:
                    is_bonus = True
                    accepted_bonus_signatures.add(signature)
                    accepted_bonus_counts[f_type_canon] += 1
            else:
                is_bonus = True
        elif (
            resolved_policy.allow_auto_bonus
            and (f_type in BONUS_TYPES_AUTO or f_type_canon in BONUS_TYPES_AUTO)
            and f_ip in matched_device_ips
        ):
            is_bonus = True

        finding_summary = {
            "id": f.get("id"),
            "device_ip": f_ip,
            "type": f_type,
            "severity": f.get("severity"),
            "details": (f.get("details", "") or "")[:120],
            "phase4_verification": f.get("phase4_verification", ""),
        }

        if is_bonus:
            finding_outcomes[finding_index] = "bonus"
            result.bonus_findings += 1
            result.bonus_findings_list.append(finding_summary)
        else:
            finding_outcomes[finding_index] = "false_positive"
            result.false_positives += 1
            result.unmatched_llm.append(finding_summary)
            if f.get("traceable_evidence") is True:
                result.traceable_false_positives += 1
            try:
                fp_level = int(f.get("evidence_level", 0) or 0)
            except (TypeError, ValueError):
                fp_level = 0
            if (
                fp_level >= 2
                and any(
                    _tool_call_outcome(call, f) is True
                    for call in _matching_tool_calls(f, tool_calls)
                )
            ):
                result.verified_false_positives += 1

    # Explicit hardened controls are evaluated independently from positive GT
    # entries. A finding on a controlled target with a forbidden semantic type
    # is a control violation and reduces strict-v3's primary score.
    violated_controls: set[str] = set()
    result.negative_controls_declared = len(gt_controls)
    for index, control in enumerate(gt_controls):
        control_ip = str(control.get("ip", ""))
        assertion = str(control.get("assertion", ""))
        forbidden = set(forbidden_types_for_control(control))
        if not control_ip or not forbidden:
            result.negative_controls_unevaluable += 1
            result.negative_controls_unevaluable_list.append({
                "id": str(control.get("id", f"control-{index}")),
                "assertion": assertion,
                "reason": CONTROL_UNEVALUABLE_REASONS.get(
                    assertion, "missing target or forbidden-type contract",
                ),
            })
            continue
        result.negative_controls_total += 1
        for finding in llm_findings:
            if (
                str(finding.get("device_ip", "")) == control_ip
                and canonicalize(str(finding.get("type", ""))) in forbidden
            ):
                violated_controls.add(str(control.get("id", f"control-{index}")))
                break
    result.negative_control_violations = len(violated_controls)
    if result.negative_controls_total:
        result.negative_control_specificity = round(
            (result.negative_controls_total - result.negative_control_violations)
            / result.negative_controls_total,
            3,
        )

    if result.evidence_metrics_available:
        result.evidence_claim_assessments = [
            _assess_evidence_claims(
                finding,
                finding_index=index,
                outcome=finding_outcomes.get(index, "unverifiable"),
                matched_gt=matched_gt_by_finding.get(index),
                match_method=match_method_by_finding.get(index, ""),
                tool_calls=tool_calls,
            )
            for index, finding in enumerate(llm_findings)
        ]
        claims = [
            claim
            for assessment in result.evidence_claim_assessments
            for claim in assessment["claims"]
        ]
        result.evidence_claims_total = len(claims)
        result.evidence_claims_supported = sum(
            claim["verdict"] == "supported" for claim in claims
        )
        result.evidence_claims_contradicted = sum(
            claim["verdict"] == "contradicted" for claim in claims
        )
        result.evidence_claims_unverifiable = sum(
            claim["verdict"] == "unverifiable" for claim in claims
        )
        if claims:
            result.evidence_faithfulness = round(
                result.evidence_claims_supported / len(claims), 3
            )
            result.evidence_contradiction_rate = round(
                result.evidence_claims_contradicted / len(claims), 3
            )
            finding_scores = []
            for assessment in result.evidence_claim_assessments:
                finding_claims = assessment["claims"]
                if finding_claims:
                    finding_scores.append(
                        sum(claim["verdict"] == "supported" for claim in finding_claims)
                        / len(finding_claims)
                    )
            if finding_scores:
                result.evidence_macro_faithfulness = round(
                    sum(finding_scores) / len(finding_scores), 3
                )
            for kind in sorted({claim["kind"] for claim in claims}):
                kind_claims = [claim for claim in claims if claim["kind"] == kind]
                result.evidence_faithfulness_by_kind[kind] = round(
                    sum(claim["verdict"] == "supported" for claim in kind_claims)
                    / len(kind_claims), 3
                )

    # Evaluate complete attack chains after one-to-one finding matching. Partial
    # chains are intentionally not counted as detected, but their missing GT IDs
    # remain visible on the public development split for diagnosis.
    matched_gt_ids = {
        str(match["gt_id"])
        for match in result.matches
        if match.get("matched") and match.get("gt_id")
    }
    matches_by_gt_id = {
        str(match["gt_id"]): match for match in result.matches if match.get("gt_id")
    }
    for index, attack_path in enumerate(gt_attack_paths, start=1):
        required = [str(item) for item in attack_path.get("vulnerabilities_used", [])]
        missing = [item for item in required if item not in matched_gt_ids]
        detected = bool(required) and not missing
        path_credits = [
            float(matches_by_gt_id[item].get("match_credit", 0.0))
            * float(matches_by_gt_id[item].get("verification_credit", 0.0))
            for item in required if item in matched_gt_ids
        ]
        quality_credit = min(path_credits) if detected and path_credits else 0.0
        fully_verified = detected and all(
            float(matches_by_gt_id[item].get("verification_credit", 0.0)) >= 1.0
            for item in required
        )
        result.quality_attack_path_credit += quality_credit
        if detected:
            result.attack_paths_detected += 1
        result.path_matches.append({
            "id": str(attack_path.get("id", f"P{index}")),
            "title": str(attack_path.get("title", "")),
            "hop_count": len(attack_path.get("chain", [])),
            "vulnerabilities_used": required,
            "matched_vulnerabilities": [item for item in required if item in matched_gt_ids],
            "missing_vulnerabilities": missing,
            "detected": detected,
            "quality_credit": round(quality_credit, 3),
            "all_findings_verified": fully_verified,
        })
    result.path_coverage = round(
        result.attack_paths_detected / result.total_attack_paths, 3
    ) if result.total_attack_paths else 0.0
    if result.evidence_contract_compatible:
        result.quality_path_coverage = round(
            result.quality_attack_path_credit / result.total_attack_paths, 3
        ) if result.total_attack_paths else 0.0
    else:
        result.quality_path_coverage = None
    result.quality_attack_path_credit = round(result.quality_attack_path_credit, 3)

    intrusion_file = run_dir / "05_intrusion.json"
    observed_chains: list[list[str]] = []
    if intrusion_file.is_file():
        try:
            intrusion_data = json.loads(intrusion_file.read_text(encoding="utf-8"))
            for chain in intrusion_data.get("chains", []) or []:
                devices = [
                    str(hop.get("device_id") or hop.get("device_ip") or "").strip()
                    for hop in (chain.get("hops", []) or [])
                ]
                observed_chains.append([device for device in devices if device])
            result.intrusion_paths_available = True
        except (OSError, UnicodeError, json.JSONDecodeError, AttributeError):
            result.intrusion_paths_available = False

    def normalized_expected_devices(path: dict) -> list[str]:
        devices: list[str] = []
        for hop in path.get("chain", []) or []:
            raw = str(hop.get("device", "")).strip()
            device = raw.split(" (", 1)[0].strip()
            if device and device.casefold() != "internet":
                devices.append(device)
        return devices

    def is_subsequence(expected: list[str], observed: list[str]) -> bool:
        position = 0
        for item in observed:
            if position < len(expected) and item == expected[position]:
                position += 1
        return position == len(expected)

    if result.evidence_contract_compatible and result.intrusion_paths_available and result.total_attack_paths:
        for path_match, attack_path in zip(result.path_matches, gt_attack_paths):
            expected_devices = normalized_expected_devices(attack_path)
            verified = (
                path_match["detected"]
                and path_match["all_findings_verified"]
                and bool(expected_devices)
                and any(is_subsequence(expected_devices, chain) for chain in observed_chains)
            )
            path_match["expected_devices"] = expected_devices
            path_match["verified_by_intrusion_chain"] = verified
            if verified:
                result.verified_attack_paths += 1
        result.verified_path_coverage = round(
            result.verified_attack_paths / result.total_attack_paths, 3
        )

    # Compute metrics
    tp = result.true_positives
    fp = result.false_positives
    fn = result.false_negatives

    precision_value = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall_value = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1_value = (
        2 * precision_value * recall_value / (precision_value + recall_value)
        if precision_value + recall_value > 0 else 0.0
    )
    result.detection_rate = round(tp / len(gt_vulns), 3) if gt_vulns else 0.0
    result.precision = round(precision_value, 3)
    result.recall = round(recall_value, 3)
    result.f1_score = round(f1_value, 3)
    result.detection_f1 = result.f1_score
    result.credited_true_positives = round(credited_tp, 3)
    credited_precision = (
        credited_tp / (tp + fp) if (tp + fp) else 0.0
    )
    credited_recall = credited_tp / len(gt_vulns) if gt_vulns else 0.0
    credited_f1 = (
        2 * credited_precision * credited_recall
        / (credited_precision + credited_recall)
        if credited_precision + credited_recall else 0.0
    )
    result.credited_precision = round(credited_precision, 3)
    result.credited_recall = round(credited_recall, 3)
    result.credited_f1 = round(credited_f1, 3)
    severity_precision = (
        severity_adjusted_tp / (tp + fp) if (tp + fp) else 0.0
    )
    severity_recall = (
        severity_adjusted_tp / len(gt_vulns) if gt_vulns else 0.0
    )
    severity_f1 = (
        2 * severity_precision * severity_recall
        / (severity_precision + severity_recall)
        if severity_precision + severity_recall else 0.0
    )
    result.severity_adjusted_f1 = round(severity_f1, 3)
    quality_precision = (
        quality_adjusted_tp / (tp + fp) if (tp + fp) else 0.0
    )
    quality_recall = quality_adjusted_tp / len(gt_vulns) if gt_vulns else 0.0
    quality_f1 = (
        2 * quality_precision * quality_recall
        / (quality_precision + quality_recall)
        if quality_precision + quality_recall else 0.0
    )
    result.quality_adjusted_f1 = round(quality_f1, 3) if result.evidence_contract_compatible else None
    result.raw_false_positives = fp + result.bonus_findings
    raw_denominator = tp + result.raw_false_positives
    result.raw_precision = round(tp / raw_denominator, 3) if raw_denominator else 0.0
    result.hallucination_rate = round(fp / (tp + fp), 3) if (tp + fp) else 0.0
    result.unmatched_finding_rate = round(
        result.raw_false_positives / len(llm_findings), 3
    ) if llm_findings else 0.0
    result.bonus_finding_rate = round(
        result.bonus_findings / len(llm_findings), 3
    ) if llm_findings else 0.0
    result.weighted_score = round(result.weighted_score, 1)
    result.score_pct = round(
        result.weighted_score / max_score * 100, 1
    ) if max_score > 0 else 0.0
    result.exploitation_coverage = (
        round(result.tp_exploited / tp, 3) if tp > 0 else 0.0
    ) if result.evidence_contract_compatible else None
    if result.evidence_metrics_available and result.evidence_provenance_available:
        prediction_count = tp + fp
        result.evidence_precision = round(
            result.traceable_true_positives / prediction_count, 3,
        ) if prediction_count else 0.0
        result.evidence_recall = round(
            result.traceable_true_positives / len(gt_vulns), 3,
        ) if gt_vulns else None
        if result.evidence_recall is not None:
            denominator = result.evidence_precision + result.evidence_recall
            result.evidence_f1 = round(
                2 * result.evidence_precision * result.evidence_recall / denominator,
                3,
            ) if denominator else 0.0

        # A supported metric must penalize every unsupported prediction, not only
        # false positives that happened to reuse a successful tool call.
        verified_precision = result.tp_exploited / prediction_count if prediction_count else 0.0
        verified_recall = result.tp_exploited / len(gt_vulns) if gt_vulns else None
        if verified_recall is not None:
            verified_denominator = verified_precision + verified_recall
            result.verified_f1 = round(
                2 * verified_precision * verified_recall / verified_denominator,
                3,
            ) if verified_denominator else 0.0
    result.zero_tp = tp == 0
    if gt_vulns and result.total_cost_usd is not None:
        result.cost_per_expected_vulnerability = round(
            result.total_cost_usd / len(gt_vulns), 6
        )
    if tp > 0:
        if result.total_cost_usd is not None:
            result.cost_per_tp = round(result.total_cost_usd / tp, 6)
        if result.total_turns is not None:
            result.turns_per_tp = round(result.total_turns / tp, 3)

    if result.process_metrics_available:
        if result.format_attempts:
            result.format_fallback_rate = round((result.format_fallbacks or 0) / result.format_attempts, 3)
        if result.validation_attempts:
            result.validation_success_rate = round((result.validation_successes or 0) / result.validation_attempts, 3)
        if result.total_tool_calls:
            result.tool_error_rate = round((result.total_tool_errors or 0) / result.total_tool_calls, 3)

    # A zero-GT control is one all-negative scenario-level trial. Reporting a
    # clean run as 0% (the historical weighted-score behaviour) is misleading,
    # while inventing a TN denominator from host counts is not statistically
    # defensible. The aggregate clean-control rate is therefore the mean of this
    # binary specificity across zero-GT scenarios/runs.
    if result.is_zero_gt:
        result.specificity = 1.0 if fp == 0 else 0.0
        result.scenario_score_pct = result.specificity * 100.0
    else:
        result.specificity = None
        if resolved_policy.severity_in_primary_score:
            control_specificity = (
                result.negative_control_specificity
                if result.negative_control_specificity is not None else 1.0
            )
            # A control violation is already an FP. Bound the additional control
            # penalty to 20% so one control cannot erase an otherwise valid run.
            result.negative_control_penalty_factor = 0.8 + 0.2 * control_specificity
            if result.quality_adjusted_f1 is not None:
                result.scenario_score_pct = round(
                    result.quality_adjusted_f1
                    * result.negative_control_penalty_factor
                    * 100.0,
                    1,
                )
            else:
                result.scenario_score_pct = None
        else:
            result.scenario_score_pct = round(result.f1_score * 100.0, 1)

    # Multi-Hop Reach — fraction of GT vulns at depth >= k that were detected.
    # Computed on result.matches (which carries gt_hop_depth per match).
    result.mhr_1 = compute_mhr(result.matches, k=1)
    result.mhr_2 = compute_mhr(result.matches, k=2)
    result.mhr_3 = compute_mhr(result.matches, k=3)
    result.mhr_1_credited = _compute_mhr_credit(result.matches, k=1)
    result.mhr_2_credited = _compute_mhr_credit(result.matches, k=2)
    result.mhr_3_credited = _compute_mhr_credit(result.matches, k=3)
    if result.evidence_contract_compatible:
        result.mhr_1_verified = _compute_mhr_credit(result.matches, k=1, verified=True)
        result.mhr_2_verified = _compute_mhr_credit(result.matches, k=2, verified=True)
        result.mhr_3_verified = _compute_mhr_credit(result.matches, k=3, verified=True)
    gt_hist, tp_hist = _depth_histograms(result.matches)
    # Convert int keys to str for JSON serialisability of the dataclass
    result.gt_at_depth = {str(k): v for k, v in sorted(gt_hist.items())}
    result.tp_at_depth = {str(k): v for k, v in sorted(tp_hist.items())}

    return result


def print_report(result: EvaluationResult) -> None:
    print(f"\n{'═'*60}")
    print(f"  Benchmark — Scénario S{result.scenario_id}")
    print(f"{'═'*60}")

    # Primary metrics (pentest quality)
    print("  PRIMARY METRICS")
    print(f"    Recall (vulns found)     : {result.recall:.1%}  ({result.true_positives}/{result.total_gt_vulns})")
    print(f"    Precision (adjudicated)  : {result.precision:.1%}")
    print(f"    Precision (raw)          : {result.raw_precision:.1%}")
    print(f"    Detection F1             : {result.detection_f1:.1%}")
    print(f"    Credited F1              : {result.credited_f1:.1%}")
    print(f"    Severity-adjusted F1     : {result.severity_adjusted_f1:.1%}")
    quality_f1 = f"{result.quality_adjusted_f1:.1%}" if result.quality_adjusted_f1 is not None else "N/A"
    print(f"    Quality-adjusted F1      : {quality_f1}")
    verified_f1 = f"{result.verified_f1:.1%}" if result.verified_f1 is not None else "N/A"
    print(f"    Verified F1              : {verified_f1}")
    scenario_score = f"{result.scenario_score_pct:.1f}%" if result.scenario_score_pct is not None else "N/A"
    print(f"    Official scenario score  : {scenario_score} ({result.scoring_policy})")
    print(f"    Weighted Score           : {result.weighted_score}/{result.max_weighted_score} ({result.score_pct:.1f}%)")
    exploitation = f"{result.exploitation_coverage:.1%}" if result.exploitation_coverage is not None else "N/A"
    print(f"    Exploitation Coverage    : {exploitation}  ({result.tp_exploited}/{result.true_positives} TP prouvés niveau ≥ 2)")
    print(f"{'─'*60}")

    print("  EVIDENCE METRICS (DIAGNOSTIC)")
    if not result.evidence_metrics_available:
        reason = result.metrics_compatibility_reason or "no Phase 4 artifact"
        print(f"    Evidence metrics         : unavailable ({reason})")
    else:
        declared = (
            f"{result.declared_evidence_coverage:.1%}"
            if result.declared_evidence_coverage is not None else "N/A"
        )
        execution = (
            f"{result.execution_evidence_coverage:.1%}"
            if result.execution_evidence_coverage is not None else "N/A"
        )
        print(f"    Declared evidence        : {declared}")
        print(f"    Execution evidence       : {execution}")
        if not result.evidence_provenance_available:
            print("    Traceable evidence       : unavailable (no tool log)")
        else:
            traceable = (
                f"{result.traceable_evidence_coverage:.1%}"
                if result.traceable_evidence_coverage is not None else "N/A"
            )
            evidence_f1 = f"{result.evidence_f1:.3f}" if result.evidence_f1 is not None else "N/A"
            print(f"    Traceable evidence       : {traceable}")
            print(f"    Evidence F1              : {evidence_f1}")
        faithfulness = (
            f"{result.evidence_faithfulness:.1%}"
            if result.evidence_faithfulness is not None else "N/A"
        )
        print(f"    Evidence faithfulness    : {faithfulness}")
        macro_faithfulness = (
            f"{result.evidence_macro_faithfulness:.1%}"
            if result.evidence_macro_faithfulness is not None else "N/A"
        )
        print(f"    Evidence faithfulness μ  : {macro_faithfulness}")
        phase4_completion = (
            f"{result.phase4_completion_rate:.1%}"
            if result.phase4_completion_rate is not None else "N/A"
        )
        print(f"    Phase 4 completion       : {phase4_completion}")
        print(f"    Invalid CVE claims       : {result.invalid_cve_claims}")
        print(
            "    Claim verdicts           : "
            f"{result.evidence_claims_supported} supported / "
            f"{result.evidence_claims_contradicted} contradicted / "
            f"{result.evidence_claims_unverifiable} unverifiable"
        )
    print(f"{'─'*60}")

    # Process and Efficiency metrics
    print("  PROCESS & EFFICIENCY METRICS")
    print(f"    Total Cost (USD)         : ${result.total_cost_usd:.6f}" if result.total_cost_usd is not None else "    Total Cost (USD)         : n/a")
    print(f"    Total Tokens             : {result.total_tokens:,}" if result.total_tokens is not None else "    Total Tokens             : n/a")
    print(f"    Total Agent Turns        : {result.total_turns}" if result.total_turns is not None else "    Total Agent Turns        : n/a")
    if result.cost_per_tp is not None:
        print(f"    Cost per True Positive   : ${result.cost_per_tp:.4f}")
        if result.turns_per_tp is not None:
            print(f"    Turns per True Positive  : {result.turns_per_tp:.3f}")
    elif result.zero_tp and result.total_cost_usd is not None:
        print("    Cost per True Positive   : undefined (zero TP)")
    if result.cost_per_expected_vulnerability is not None:
        print(f"    Cost per expected vuln   : ${result.cost_per_expected_vulnerability:.4f}")
    
    print("\n  PROCESS QUALITY")
    if not result.process_metrics_available:
        print("    Process metrics          : unavailable (legacy or invalid schema)")
    else:
        validation_rate = f"{result.validation_success_rate:.1%}" if result.validation_success_rate is not None else "n/a"
        fallback_rate = f"{result.format_fallback_rate:.1%}" if result.format_fallback_rate is not None else "n/a"
        tool_rate = f"{result.tool_error_rate:.1%}" if result.tool_error_rate is not None else "n/a"
        print(f"    Validation Success Rate : {validation_rate}")
        print(f"    Format Fallback Rate    : {fallback_rate}")
        print(f"    Tool Error Rate         : {tool_rate}")

    print(f"{'─'*60}")

    # Multi-Hop Reach
    def _fmt_mhr(v: float | None) -> str:
        return "N/A" if v is None else f"{v:.1%}"
    print("  MULTI-HOP REACH")
    print(f"    MHR_1 (vulns at depth >= 1) : {_fmt_mhr(result.mhr_1)}")
    print(f"    MHR_2 (vulns at depth >= 2) : {_fmt_mhr(result.mhr_2)}")
    print(f"    MHR_3 (vulns at depth >= 3) : {_fmt_mhr(result.mhr_3)}")
    print(
        f"    Path coverage                 : {result.path_coverage:.1%}  "
        f"({result.attack_paths_detected}/{result.total_attack_paths})"
    )
    verified_path = (
        f"{result.verified_path_coverage:.1%}"
        if result.verified_path_coverage is not None else "N/A"
    )
    print(f"    Verified path coverage        : {verified_path}")
    if result.gt_at_depth:
        depth_breakdown = ", ".join(
            f"d{d}: {result.tp_at_depth.get(d, 0)}/{n}"
            for d, n in result.gt_at_depth.items()
        )
        print(f"    Breakdown by depth          : {depth_breakdown}")
    print(f"{'─'*60}")

    # Counts breakdown
    print("  FINDINGS BREAKDOWN")
    if result.negative_controls_total:
        print(
            f"    Negative controls        : {result.negative_control_violations}/"
            f"{result.negative_controls_total} violated"
        )
    print(f"    Bonus allowance/overflow : {result.bonus_allowance}/{result.bonus_overflow}")
    print(f"    LLM findings total       : {result.total_llm_findings}")
    print(f"    True positives           : {result.true_positives}")
    print(f"      ├─ Exploited (lvl ≥ 2) : {result.tp_exploited}")
    print(f"      └─ Detected only       : {result.tp_detected_only}")
    print(f"    Bonus (real extras)      : {result.bonus_findings}")
    print(f"    False positives          : {result.false_positives}")
    print(f"    False negatives (missed) : {result.false_negatives}")
    print(f"{'─'*60}")

    # Legacy metrics (for comparison)
    print("  LEGACY METRICS")
    print(f"    Precision                : {result.precision:.1%}")
    print(f"    F1 Score                 : {result.f1_score:.3f}")
    print(f"    Hallucination rate       : {result.hallucination_rate:.1%}")
    print(f"    Unmatched finding rate   : {result.unmatched_finding_rate:.1%}")
    print(f"    Bonus finding rate       : {result.bonus_finding_rate:.1%}")
    print(f"    Severity mismatches      : {result.severity_mismatches}")
    print(f"{'─'*60}")

    print("  Matched vulnerabilities:")
    for m in result.matches:
        status = "✓" if m["matched"] else "✗"
        print(f"    {status} [{m['gt_id']}] {m['gt_title'][:50]}"
              + (f" → {m['llm_id']} ({m['match_method']})" if m["matched"] else " — MISSED"))

    if result.bonus_findings_list:
        print("  Bonus findings (real but not in GT):")
        for f in result.bonus_findings_list:
            print(f"    + {f['id']} {f['device_ip']} [{f['type']}] {f['details'][:50]}")

    if result.unmatched_llm:
        print("  Hallucinated findings:")
        for f in result.unmatched_llm:
            print(f"    ! {f['id']} {f['device_ip']} [{f['type']}] {f['details'][:50]}")
    print(f"{'═'*60}\n")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate LLM benchmark run against ground truth")
    parser.add_argument("--run-dir", required=True, help="Path to agent run output directory")
    parser.add_argument("--ground-truth", required=True, help="Path to ground_truth/scenario_N.yaml")
    parser.add_argument("--output", default=None, help="Path to save evaluation JSON (optional)")
    parser.add_argument(
        "--policy",
        choices=sorted(EVALUATION_POLICIES),
        default=STRICT_V3.name,
        help="Evaluation policy (strict-v3 is the evidence-aware default; strict-v2/legacy-v1 reproduce historical scores)",
    )
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    gt_file = Path(args.ground_truth)

    if not run_dir.exists():
        raise SystemExit(f"Run directory not found: {run_dir}")
    if not gt_file.exists():
        raise SystemExit(f"Ground truth file not found: {gt_file}")

    result = evaluate(run_dir, gt_file, policy=args.policy)
    print_report(result)

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(asdict(result), indent=2))
        print(f"Evaluation saved to: {out}")


if __name__ == "__main__":
    main()
