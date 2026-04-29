"""Benchmark evaluator — compare LLM findings against ground truth.

Usage:
    python3 -m src.benchmark.evaluator --run-dir output/agent/20250326_120000 \
        --ground-truth benchmarks/ground_truth/scenario_2.yaml \
        --output results/evaluation.json
"""
from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from datetime import date

import yaml

from src.agent.vuln_taxonomy import canonicalize, NOISE_TYPES


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
    hallucination_rate: float = 0.0

    # Weighted score: critical=4, high=3, medium=2, low=1
    # ip+category (loose) matches count as 0.5x to penalise guesses
    weighted_score: float = 0.0
    max_weighted_score: int = 0
    score_pct: float = 0.0  # weighted_score / max_weighted_score * 100

    # Primary metrics for pentest quality assessment
    exploitation_coverage: float = 0.0  # % of TP findings with evidence_level >= 2
    tp_exploited: int = 0               # TP findings with evidence_level >= 2
    tp_detected_only: int = 0           # TP findings with evidence_level < 2

    # Multi-Hop Reach (MHR) — fraction of GT vulns at depth >= k that were detected.
    # None when no GT entry exists at that depth (metric undefined for that scenario,
    # e.g. a flat topology has MHR_1 = MHR_2 = MHR_3 = None).
    mhr_1: float | None = None
    mhr_2: float | None = None
    mhr_3: float | None = None
    gt_at_depth: dict = field(default_factory=dict)  # {0: 5, 1: 3, 2: 1} — GT counts per depth bucket
    tp_at_depth: dict = field(default_factory=dict)  # {0: 4, 1: 2, 2: 0} — TP counts per depth bucket

    # Details
    matches: list[dict] = field(default_factory=list)
    unmatched_llm: list[dict] = field(default_factory=list)
    bonus_findings_list: list[dict] = field(default_factory=list)


# ── Matching logic ────────────────────────────────────────────────────────────

def _match_by_cve(gt_vuln: dict, llm_findings: list[dict]) -> dict | None:
    """Match ground truth vuln to LLM finding by CVE ID (case-insensitive)."""
    gt_cve = gt_vuln.get("cve")
    if not gt_cve:
        return None
    gt_cve_norm = gt_cve.upper()
    for f in llm_findings:
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
    """Loose match: same IP + exact severity (last resort). Exact severity required to avoid
    cross-vuln collisions when multiple findings share the same IP."""
    gt_ip = gt_vuln.get("ip", "")
    gt_sev = gt_vuln.get("severity", "low").lower()
    for f in llm_findings:
        if f.get("device_ip") != gt_ip:
            continue
        llm_sev = (f.get("severity") or "low").lower()
        if llm_sev == gt_sev:
            return f
    return None


def match_vuln(gt_vuln: dict, llm_findings: list[dict]) -> tuple[dict | None, str]:
    """Try to match a ground truth vuln to an LLM finding. Returns (finding, method)."""
    f = _match_by_cve(gt_vuln, llm_findings)
    if f:
        return f, "cve"
    f = _match_by_ip_and_type(gt_vuln, llm_findings)
    if f:
        return f, "ip+type"
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

    `matches` is the result.matches list (asdict'd MatchResult), each entry has
    keys 'matched' (bool) and 'gt_hop_depth' (int).

    The interpretation: how good is the system at finding vulnerabilities that
    require crossing at least k network segments from the attacker's entry point?
    Mono-host LLM agents (PentestGPT, CAI per-IP, etc.) are expected to score
    near zero on MHR_2 and MHR_3 by construction — they cannot pivot. Network-
    native pipelines should score significantly higher.
    """
    gt_at_k = [m for m in matches if int(m.get("gt_hop_depth", 0)) >= k]
    if not gt_at_k:
        return None
    tp_at_k = sum(1 for m in gt_at_k if m.get("matched"))
    return round(tp_at_k / len(gt_at_k), 3)


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

# Phase 4 statuses that mean "test ran but vuln not exploitable" or "tool error"
# — they are excluded from the LLM findings so they don't count as false positives.
_SKIPPED_PHASE4_STATUSES: frozenset[str] = frozenset({"FAILED"})


def _load_llm_findings(run_dir: Path) -> list[dict]:
    """Return LLM findings from a run dir.

    Prefers `04_exploitation.json` (post-exploitation), drops Phase 4 FAILED statuses,
    but rescues Phase 3 CONFIRMED findings that were FAILed in Phase 4.
    Falls back entirely to `03_vuln_analysis.json` when no Phase 4 file exists.
    Raises FileNotFoundError if neither exists.
    """
    exploit_file = run_dir / "04_exploitation.json"
    vuln_file = run_dir / "03_vuln_analysis.json"

    p3_by_id: dict[str, dict] = {}
    if vuln_file.exists():
        for v in json.loads(vuln_file.read_text()).get("vulnerabilities", []):
            vid = v.get("id", "")
            if vid:
                p3_by_id[vid] = v

    if exploit_file.exists():
        raw = json.loads(exploit_file.read_text())
        # Accept both "tests" (current pipeline format) and "vulnerabilities"
        # (legacy MiniMax format where Phase 4 reused Phase 3 structure).
        test_list = raw.get("tests") or raw.get("vulnerabilities") or []
        findings = []
        for t in test_list:
            vuln_type = t.get("vuln_type") or t.get("type", "")
            if vuln_type in NOISE_TYPES:
                continue
            status = t.get("status", "")
            if status in _SKIPPED_PHASE4_STATUSES:
                # Phase 3 CONFIRMED over Phase 4 FAILED: rescue the P3 finding.
                vuln_id = t.get("vuln_id") or t.get("id", "")
                p3 = p3_by_id.get(vuln_id)
                if p3 and p3.get("exploitation_status") in ("confirmed", "suspected") and p3.get("type", "") not in NOISE_TYPES:
                    findings.append({
                        "id": p3.get("id", ""),
                        "device_id": p3.get("device_id", ""),
                        "device_ip": p3.get("device_ip", ""),
                        "type": p3.get("type", ""),
                        "severity": p3.get("severity", ""),
                        "details": p3.get("details", ""),
                        "evidence": p3.get("evidence", ""),
                        "evidence_level": 1,
                        "cve_ids": p3.get("cve_ids", []),
                    })
                continue
            findings.append({
                "id": t.get("vuln_id") or t.get("id", ""),
                "device_id": t.get("device_id", ""),
                "device_ip": t.get("device_ip", ""),
                "type": vuln_type,
                "severity": t.get("severity", ""),
                "details": t.get("description") or t.get("details", ""),
                "evidence": t.get("evidence", ""),
                "evidence_level": t.get("evidence_level", 0),
                "cve_ids": _sanitize_cve_ids(t.get("cve_ids", [])),
            })
        if findings:
            return findings
        # else: fall through to 03_vuln_analysis.json fallback

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


def evaluate(run_dir: Path, ground_truth_file: Path) -> EvaluationResult:
    # Load ground truth
    gt_data = yaml.safe_load(ground_truth_file.read_text())
    gt_vulns = gt_data.get("vulnerabilities", [])
    scenario_id = str(gt_data.get("scenario_id", "?"))
    weights = gt_data.get("scoring", {}).get("weights", {"critical": 4, "high": 3, "medium": 2, "low": 1})
    bonus_types = set(gt_data.get("bonus_types", []))

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

    result = EvaluationResult(
        scenario_id=scenario_id,
        run_dir=str(run_dir),
        ground_truth_file=str(ground_truth_file),
        total_gt_vulns=len(gt_vulns),
        total_llm_findings=len(llm_findings),
        max_weighted_score=max_score,
    )

    # Use composite key id|device_ip to avoid collisions when multiple devices share the same VULN-00x IDs
    matched_llm_keys: set[str] = set()

    def _llm_key(f: dict) -> str:
        return f"{f.get('id', '')}|{f.get('device_ip', '')}"

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
    matches_by_gt_index: dict[int, tuple] = {}

    # Pass 1: Exact CVE + ip+type matches only (no loose ip+severity)
    for gt_index, gt in sorted_gt:
        remaining = [f for f in llm_findings if _llm_key(f) not in matched_llm_keys]
        # Try exact matches only
        match = _match_by_cve(gt, remaining)
        method = "cve" if match else ""
        if not match:
            match = _match_by_ip_and_type(gt, remaining)
            method = "ip+type" if match else ""
        if match:
            matched_llm_keys.add(_llm_key(match))
        matches_by_gt_index[gt_index] = (match, method)

    # Pass 2: Loose ip+severity matches for GT vulns still unmatched
    for gt_index, gt in sorted_gt:
        if matches_by_gt_index[gt_index][0] is not None:
            continue
        remaining = [f for f in llm_findings if _llm_key(f) not in matched_llm_keys]
        match = _match_by_ip_and_service(gt, remaining)
        if match:
            matched_llm_keys.add(_llm_key(match))
            matches_by_gt_index[gt_index] = (match, "ip+category")

    # Re-iterate in original order to preserve report output
    for gt_index, gt in enumerate(gt_vulns):
        match, method = matches_by_gt_index[gt_index]
        severity = gt.get("severity", "low")
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
            mr.llm_id = match.get("id", "")
            mr.llm_type = match.get("type", "")
            mr.llm_severity = match.get("severity", "")
            mr.match_method = method
            mr.severity_match = (
                (match.get("severity") or "").lower() == severity.lower()
            )
            result.true_positives += 1
            if not mr.severity_match:
                result.severity_mismatches += 1

            # Exploitation coverage: count TPs with evidence_level >= 2 (exploited)
            evidence_level = match.get("evidence_level", 0)
            try:
                evidence_level = int(evidence_level)
            except (TypeError, ValueError):
                evidence_level = 0
            if evidence_level >= 2:
                result.tp_exploited += 1
            else:
                result.tp_detected_only += 1

            # Scoring penalties:
            #   ip+category (loose match)  → 0.5x  (structural ambiguity)
            #   severity mismatch          → 0.75x  (right vuln, wrong impact)
            #   both combined              → 0.5 * 0.75 = 0.375x
            score_weight = weight
            if method == "ip+category":
                score_weight *= 0.5
            if not mr.severity_match:
                score_weight *= 0.75
            result.weighted_score += score_weight
        else:
            result.false_negatives += 1

        result.matches.append(asdict(mr))

    # Devices that have at least one matched GT finding — used to classify "bonus" findings.
    matched_device_ips: set[str] = {
        m["gt_ip"] for m in result.matches if m.get("matched") and m.get("gt_ip")
    }

    # Classify unmatched LLM findings: bonus (real but not in GT) vs false positive (hallucination)
    # Bonus conditions:
    #   - explicit in ground_truth.yaml bonus_types list, OR
    #   - type is in BONUS_TYPES_AUTO AND the device has other matched findings (real device)
    for f in llm_findings:
        if _llm_key(f) in matched_llm_keys:
            continue

        f_type = f.get("type", "")
        f_type_canon = canonicalize(f_type)
        f_ip = f.get("device_ip", "")
        is_bonus = False

        if bonus_types and (f_type in bonus_types or f_type_canon in bonus_types):
            is_bonus = True
        elif (f_type in BONUS_TYPES_AUTO or f_type_canon in BONUS_TYPES_AUTO) and f_ip in matched_device_ips:
            is_bonus = True

        finding_summary = {
            "id": f.get("id"),
            "device_ip": f_ip,
            "type": f_type,
            "severity": f.get("severity"),
            "details": (f.get("details", "") or "")[:120],
        }

        if is_bonus:
            result.bonus_findings += 1
            result.bonus_findings_list.append(finding_summary)
        else:
            result.false_positives += 1
            result.unmatched_llm.append(finding_summary)

    # Compute metrics
    tp = result.true_positives
    fp = result.false_positives
    fn = result.false_negatives

    result.detection_rate = round(tp / len(gt_vulns), 3) if gt_vulns else 0.0
    result.precision = round(tp / (tp + fp), 3) if (tp + fp) > 0 else 0.0
    result.recall = round(tp / (tp + fn), 3) if (tp + fn) > 0 else 0.0
    result.f1_score = round(
        2 * result.precision * result.recall / (result.precision + result.recall), 3
    ) if (result.precision + result.recall) > 0 else 0.0
    result.hallucination_rate = round(fp / len(llm_findings), 3) if llm_findings else 0.0
    result.weighted_score = round(result.weighted_score, 1)
    result.score_pct = round(
        result.weighted_score / max_score * 100, 1
    ) if max_score > 0 else 0.0
    result.exploitation_coverage = round(
        result.tp_exploited / tp, 3
    ) if tp > 0 else 0.0

    # Multi-Hop Reach — fraction of GT vulns at depth >= k that were detected.
    # Computed on result.matches (which carries gt_hop_depth per match).
    result.mhr_1 = compute_mhr(result.matches, k=1)
    result.mhr_2 = compute_mhr(result.matches, k=2)
    result.mhr_3 = compute_mhr(result.matches, k=3)
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
    print(f"    Weighted Score           : {result.weighted_score}/{result.max_weighted_score} ({result.score_pct:.1f}%)")
    print(f"    Exploitation Coverage    : {result.exploitation_coverage:.1%}  ({result.tp_exploited}/{result.true_positives} TP prouvés niveau ≥ 2)")
    print(f"{'─'*60}")

    # Multi-Hop Reach
    def _fmt_mhr(v: float | None) -> str:
        return "N/A" if v is None else f"{v:.1%}"
    print("  MULTI-HOP REACH")
    print(f"    MHR_1 (vulns at depth >= 1) : {_fmt_mhr(result.mhr_1)}")
    print(f"    MHR_2 (vulns at depth >= 2) : {_fmt_mhr(result.mhr_2)}")
    print(f"    MHR_3 (vulns at depth >= 3) : {_fmt_mhr(result.mhr_3)}")
    if result.gt_at_depth:
        depth_breakdown = ", ".join(
            f"d{d}: {result.tp_at_depth.get(d, 0)}/{n}"
            for d, n in result.gt_at_depth.items()
        )
        print(f"    Breakdown by depth          : {depth_breakdown}")
    print(f"{'─'*60}")

    # Counts breakdown
    print("  FINDINGS BREAKDOWN")
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
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    gt_file = Path(args.ground_truth)

    if not run_dir.exists():
        raise SystemExit(f"Run directory not found: {run_dir}")
    if not gt_file.exists():
        raise SystemExit(f"Ground truth file not found: {gt_file}")

    result = evaluate(run_dir, gt_file)
    print_report(result)

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(asdict(result), indent=2))
        print(f"Evaluation saved to: {out}")


if __name__ == "__main__":
    main()
