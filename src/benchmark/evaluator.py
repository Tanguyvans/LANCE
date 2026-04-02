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

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0,
                 "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

# Ground-truth category → LLM vuln type(s)
CATEGORY_TO_TYPE = {
    "misconfiguration":   {"no_auth", "missing_header", "version_leak"},
    "cve":                {"known_cve", "terrapin", "weak_cipher"},
    "default_credentials": {"no_auth"},
    "data_exposure":      {"missing_header", "version_leak", "no_auth"},
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
    match_method: str = ""  # "cve", "ip+type", "ip+category"


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

    # Metrics
    detection_rate: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    hallucination_rate: float = 0.0

    # Weighted score (critical=4, high=3, medium=2, low=1)
    weighted_score: float = 0.0
    max_weighted_score: int = 0

    # Details
    matches: list[dict] = field(default_factory=list)
    unmatched_llm: list[dict] = field(default_factory=list)


# ── Matching logic ────────────────────────────────────────────────────────────

def _match_by_cve(gt_vuln: dict, llm_findings: list[dict]) -> dict | None:
    """Match ground truth vuln to LLM finding by CVE ID."""
    gt_cve = gt_vuln.get("cve")
    if not gt_cve:
        return None
    for f in llm_findings:
        if gt_cve in (f.get("cve_ids") or []):
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
    """Loose match: same IP, any finding (last resort)."""
    gt_ip = gt_vuln.get("ip", "")
    for f in llm_findings:
        if f.get("device_ip") == gt_ip:
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
    max_score = gt_data.get("scoring", {}).get("max_weighted_score", 0)
    weights = gt_data.get("scoring", {}).get("weights", {"critical": 4, "high": 3, "medium": 2, "low": 1})
    bonus_types = set(gt_data.get("bonus_types", []))

    # Load LLM findings
    vuln_file = run_dir / "03_vuln_analysis.json"
    if not vuln_file.exists():
        raise FileNotFoundError(f"03_vuln_analysis.json not found in {run_dir}")

    llm_data = json.loads(vuln_file.read_text())
    llm_findings = llm_data.get("vulnerabilities", [])

    result = EvaluationResult(
        scenario_id=scenario_id,
        run_dir=str(run_dir),
        ground_truth_file=str(ground_truth_file),
        total_gt_vulns=len(gt_vulns),
        total_llm_findings=len(llm_findings),
        max_weighted_score=max_score,
    )

    matched_llm_ids: set[str] = set()

    for gt in gt_vulns:
        match, method = match_vuln(gt, llm_findings)
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
            matched_llm_ids.add(match.get("id", ""))
            result.true_positives += 1
            result.weighted_score += weight
        else:
            result.false_negatives += 1

        result.matches.append(asdict(mr))

    # False positives = LLM findings not matched to any GT vuln
    # Bonus findings (e.g. weak_cipher, missing_header) are expected extras — not penalised
    for f in llm_findings:
        if f.get("id") not in matched_llm_ids:
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
    print(f"  Weighted Score   : {result.weighted_score} / {result.max_weighted_score}")
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
