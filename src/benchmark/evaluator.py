"""Benchmark evaluator — compare LLM findings against ground truth.

Usage:
    python3 -m src.benchmark.evaluator --run-dir output/agent/20250326_120000 \
        --ground-truth benchmarks/ground_truth/scenario_2.yaml \
        --output results/evaluation.json
"""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path

import yaml


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
        "missing_header", "version_leak", "no_auth", "data_exposure",
        "directory_listing", "credential_exposure", "sensitive_data_exposure",
        "info_disclosure", "config_exposure", "file_disclosure",
        "plaintext_credentials", "cleartext_storage", "backup_exposure",
    },
    "no_authentication":   {
        "no_auth", "missing_header", "no_auth_required", "unauthenticated_access",
        "missing_authentication", "insecure_access", "open_access",
        "unauthenticated", "auth_bypass", "redis_no_auth", "coap_no_auth",
        "modbus_no_auth", "nodered_no_auth", "api_no_auth",
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
    bonus_findings: int = 0   # expected extras (weak_cipher, missing_header…) — not penalised
    total_llm_findings: int = 0
    severity_mismatches: int = 0  # found right vuln, wrong severity

    # Metrics
    detection_rate: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    hallucination_rate: float = 0.0

    # Weighted score (critical=4, high=3, medium=2, low=1)
    # ip+category (loose) matches count as 0.5 to penalise guesses
    weighted_score: float = 0.0
    max_weighted_score: int = 0
    score_pct: float = 0.0  # weighted_score / max_weighted_score * 100

    # Details
    matches: list[dict] = field(default_factory=list)
    unmatched_llm: list[dict] = field(default_factory=list)


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


def _match_by_ip_and_type(gt_vuln: dict, llm_findings: list[dict]) -> dict | None:
    """Match by IP + compatible type or category."""
    gt_ip = gt_vuln.get("ip", "")
    gt_category = gt_vuln.get("category", "")
    compatible_types = CATEGORY_TO_TYPE.get(gt_category, set())

    for f in llm_findings:
        if f.get("device_ip") != gt_ip:
            continue
        if f.get("type") in compatible_types:
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


# ── Evaluator ─────────────────────────────────────────────────────────────────

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

    # Load LLM findings — prefer 04_exploitation.json if it exists (post-exploit),
    # otherwise fall back to 03_vuln_analysis.json (detection only).
    exploit_file = run_dir / "04_exploitation.json"
    vuln_file = run_dir / "03_vuln_analysis.json"

    if exploit_file.exists():
        raw = json.loads(exploit_file.read_text())
        # 04_exploitation.json uses "tests" key with different field names
        raw_tests = raw.get("tests", [])
        llm_findings = []
        for t in raw_tests:
            # Skip findings that failed exploitation or errored (false positives eliminated)
            if t.get("status") in ("FAILED", "ERROR"):
                continue
            llm_findings.append({
                "id": t.get("vuln_id", ""),
                "device_id": t.get("device_id", ""),
                "device_ip": t.get("device_ip", ""),
                "type": t.get("vuln_type", ""),
                "severity": t.get("severity", ""),
                "details": t.get("description", ""),
                "evidence": t.get("evidence", ""),
                "cve_ids": t.get("cve_ids", []),
            })
    elif vuln_file.exists():
        llm_data = json.loads(vuln_file.read_text())
        llm_findings = llm_data.get("vulnerabilities", [])
    else:
        raise FileNotFoundError(
            f"Neither 04_exploitation.json nor 03_vuln_analysis.json found in {run_dir}"
        )

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

    for gt in gt_vulns:
        # Exclude already-matched findings to prevent one LLM finding counting as multiple TPs
        remaining = [f for f in llm_findings if _llm_key(f) not in matched_llm_keys]
        match, method = match_vuln(gt, remaining)
        severity = gt.get("severity", "low")
        weight = weights.get(severity, 1)

        mr = MatchResult(
            gt_id=gt["id"],
            gt_title=gt["title"],
            gt_device=gt.get("device", ""),
            gt_ip=gt.get("ip", ""),
            gt_severity=severity,
            matched=match is not None,
        )

        if match:
            mr.llm_id = match.get("id", "")
            mr.llm_type = match.get("type", "")
            mr.llm_severity = match.get("severity", "")
            mr.match_method = method
            mr.severity_match = (
                (match.get("severity") or "").lower() == severity.lower()
            )
            matched_llm_keys.add(_llm_key(match))
            result.true_positives += 1
            if not mr.severity_match:
                result.severity_mismatches += 1
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

    # False positives = LLM findings not matched to any GT vuln
    # Bonus findings (e.g. weak_cipher, missing_header) are expected extras — not penalised
    for f in llm_findings:
        if _llm_key(f) not in matched_llm_keys:
            if bonus_types and f.get("type") in bonus_types:
                result.bonus_findings += 1
                continue
            result.false_positives += 1
            result.unmatched_llm.append({
                "id": f.get("id"),
                "device_ip": f.get("device_ip"),
                "type": f.get("type"),
                "severity": f.get("severity"),
                "details": f.get("details", "")[:120],
            })

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

    return result


def print_report(result: EvaluationResult) -> None:
    print(f"\n{'═'*60}")
    print(f"  Benchmark — Scénario S{result.scenario_id}")
    print(f"{'═'*60}")
    print(f"  GT vulns      : {result.total_gt_vulns}")
    print(f"  LLM findings  : {result.total_llm_findings}")
    print(f"  True positives: {result.true_positives}")
    print(f"  False positives (hallucinations): {result.false_positives}")
    print(f"  Bonus findings (expected extras): {result.bonus_findings}")
    print(f"  False negatives (missed): {result.false_negatives}")
    print(f"{'─'*60}")
    print(f"  Detection Rate   : {result.detection_rate:.1%}")
    print(f"  Precision        : {result.precision:.1%}")
    print(f"  Recall           : {result.recall:.1%}")
    print(f"  F1 Score         : {result.f1_score:.3f}")
    print(f"  Hallucination    : {result.hallucination_rate:.1%}")
    print(f"  Severity mismatches: {result.severity_mismatches}")
    print(f"  Weighted Score   : {result.weighted_score} / {result.max_weighted_score} ({result.score_pct:.1f}%)")
    print(f"{'─'*60}")
    print("  Matched vulnerabilities:")
    for m in result.matches:
        status = "✓" if m["matched"] else "✗"
        print(f"    {status} [{m['gt_id']}] {m['gt_title'][:50]}"
              + (f" → {m['llm_id']} ({m['match_method']})" if m["matched"] else " — MISSED"))
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
