"""Tests for src/benchmark/evaluator.py."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from src.benchmark.evaluator import (
    CATEGORY_TO_TYPE,
    EvaluationResult,
    MatchResult,
    _match_by_cve,
    _match_by_ip_and_service,
    _match_by_ip_and_type,
    evaluate,
    match_vuln,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _gt(id="V1", ip="192.168.100.11", severity="high", category="misconfiguration",
        cve=None, device="s1-mqtt"):
    return {"id": id, "ip": ip, "severity": severity, "category": category,
            "cve": cve, "device": device, "title": f"Vuln {id}"}


def _finding(id="F1", ip="192.168.100.11", type="no_auth", severity="high",
             cve_ids=None):
    return {"id": id, "device_ip": ip, "type": type, "severity": severity,
            "cve_ids": cve_ids or [], "details": "test finding"}


def _write_run(tmp_path: Path, findings: list[dict]) -> Path:
    """Write a minimal 03_vuln_analysis.json and return the run dir."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "03_vuln_analysis.json").write_text(
        json.dumps({"vulnerabilities": findings})
    )
    return run_dir


def _write_gt(tmp_path: Path, vulns: list[dict], scenario_id="1",
              bonus_types=None, weights=None, max_score=None) -> Path:
    """Write a minimal ground truth YAML and return its path."""
    w = weights or {"critical": 4, "high": 3, "medium": 2, "low": 1}
    if max_score is None:
        max_score = sum(w.get(v.get("severity", "low"), 1) for v in vulns)
    data = {
        "scenario_id": scenario_id,
        "vulnerabilities": vulns,
        "scoring": {"max_weighted_score": max_score, "weights": w},
        "bonus_types": bonus_types or [],
    }
    gt_file = tmp_path / f"scenario_{scenario_id}.yaml"
    gt_file.write_text(yaml.dump(data))
    return gt_file


# ── CATEGORY_TO_TYPE completeness ─────────────────────────────────────────────

class TestCategoryToType:
    def test_standard_categories_present(self):
        for cat in ("misconfiguration", "cve", "default_credentials", "data_exposure"):
            assert cat in CATEGORY_TO_TYPE, f"Missing category: {cat}"

    def test_no_authentication_present(self):
        assert "no_authentication" in CATEGORY_TO_TYPE
        assert "no_auth" in CATEGORY_TO_TYPE["no_authentication"]

    def test_code_injection_present(self):
        assert "code_injection" in CATEGORY_TO_TYPE
        assert len(CATEGORY_TO_TYPE["code_injection"]) > 0

    def test_all_values_are_sets(self):
        for cat, types in CATEGORY_TO_TYPE.items():
            assert isinstance(types, set), f"{cat} should be a set"


# ── Unit tests: matching functions ────────────────────────────────────────────

class TestMatchByCve:
    def test_exact_match(self):
        gt = _gt(cve="CVE-2023-48795")
        findings = [_finding(cve_ids=["CVE-2023-48795"])]
        assert _match_by_cve(gt, findings) is findings[0]

    def test_no_cve_in_gt_returns_none(self):
        gt = _gt(cve=None)
        findings = [_finding(cve_ids=["CVE-2023-48795"])]
        assert _match_by_cve(gt, findings) is None

    def test_cve_not_in_findings_returns_none(self):
        gt = _gt(cve="CVE-2023-48795")
        findings = [_finding(cve_ids=["CVE-2021-0001"])]
        assert _match_by_cve(gt, findings) is None

    def test_empty_findings(self):
        gt = _gt(cve="CVE-2023-48795")
        assert _match_by_cve(gt, []) is None

    def test_finding_with_no_cve_ids(self):
        gt = _gt(cve="CVE-2023-48795")
        findings = [_finding()]  # cve_ids=[]
        assert _match_by_cve(gt, findings) is None


class TestMatchByIpAndType:
    def test_match_misconfiguration_no_auth(self):
        gt = _gt(category="misconfiguration", ip="192.168.100.11")
        findings = [_finding(ip="192.168.100.11", type="no_auth")]
        assert _match_by_ip_and_type(gt, findings) is findings[0]

    def test_match_cve_terrapin(self):
        gt = _gt(category="cve", ip="192.168.100.14")
        findings = [_finding(ip="192.168.100.14", type="terrapin")]
        assert _match_by_ip_and_type(gt, findings) is findings[0]

    def test_match_no_authentication_category(self):
        gt = _gt(category="no_authentication", ip="192.168.100.15")
        findings = [_finding(ip="192.168.100.15", type="no_auth")]
        assert _match_by_ip_and_type(gt, findings) is findings[0]

    def test_match_code_injection_category(self):
        gt = _gt(category="code_injection", ip="192.168.100.12")
        findings = [_finding(ip="192.168.100.12", type="rce")]
        assert _match_by_ip_and_type(gt, findings) is findings[0]

    def test_wrong_ip_no_match(self):
        gt = _gt(category="misconfiguration", ip="192.168.100.11")
        findings = [_finding(ip="192.168.100.99", type="no_auth")]
        assert _match_by_ip_and_type(gt, findings) is None

    def test_wrong_type_no_match(self):
        gt = _gt(category="default_credentials", ip="192.168.100.11")
        findings = [_finding(ip="192.168.100.11", type="terrapin")]
        assert _match_by_ip_and_type(gt, findings) is None

    def test_unknown_category_no_match(self):
        gt = _gt(category="unknown_category", ip="192.168.100.11")
        findings = [_finding(ip="192.168.100.11", type="no_auth")]
        assert _match_by_ip_and_type(gt, findings) is None


class TestMatchByIpAndService:
    def test_any_finding_on_same_ip(self):
        gt = _gt(ip="192.168.100.11")
        findings = [_finding(ip="192.168.100.11", type="version_leak")]
        assert _match_by_ip_and_service(gt, findings) is findings[0]

    def test_different_ip_no_match(self):
        gt = _gt(ip="192.168.100.11")
        findings = [_finding(ip="192.168.100.99")]
        assert _match_by_ip_and_service(gt, findings) is None

    def test_empty_findings(self):
        gt = _gt(ip="192.168.100.11")
        assert _match_by_ip_and_service(gt, []) is None


class TestMatchVuln:
    def test_priority_cve_over_ip_type(self):
        gt = _gt(cve="CVE-2023-48795", category="cve", ip="192.168.100.11")
        f_cve  = _finding(id="F1", ip="192.168.100.11", type="terrapin",
                          cve_ids=["CVE-2023-48795"])
        f_type = _finding(id="F2", ip="192.168.100.11", type="terrapin")
        match, method = match_vuln(gt, [f_type, f_cve])
        assert match is f_cve
        assert method == "cve"

    def test_ip_type_before_loose(self):
        # f_unknown has an unrecognised type → would only match via loose (ip+category)
        # f_type has a compatible type → should win via ip+type even if listed second
        gt = _gt(category="misconfiguration", ip="192.168.100.11")
        f_unknown = _finding(id="F1", ip="192.168.100.11", type="totally_unknown")
        f_type    = _finding(id="F2", ip="192.168.100.11", type="no_auth")
        match, method = match_vuln(gt, [f_unknown, f_type])
        assert match is f_type
        assert method == "ip+type"

    def test_fallback_to_loose(self):
        gt = _gt(category="misconfiguration", ip="192.168.100.11")
        findings = [_finding(ip="192.168.100.11", type="unknown_type")]
        match, method = match_vuln(gt, findings)
        assert match is findings[0]
        assert method == "ip+category"

    def test_no_match(self):
        gt = _gt(ip="192.168.100.11")
        findings = [_finding(ip="192.168.100.99")]
        match, method = match_vuln(gt, findings)
        assert match is None
        assert method == ""


# ── evaluate() integration tests ─────────────────────────────────────────────

class TestEvaluateDoubleMatching:
    """One LLM finding must not count as multiple TPs."""

    def test_single_finding_matches_only_one_gt(self, tmp_path):
        # Two GT vulns on same IP, only one LLM finding
        vulns = [
            _gt(id="V1", ip="192.168.100.11", category="misconfiguration", severity="high"),
            _gt(id="V2", ip="192.168.100.11", category="default_credentials", severity="high"),
        ]
        findings = [_finding(id="F1", ip="192.168.100.11", type="no_auth")]
        run_dir = _write_run(tmp_path, findings)
        gt_file = _write_gt(tmp_path, vulns, max_score=6)

        result = evaluate(run_dir, gt_file)
        assert result.true_positives == 1
        assert result.false_negatives == 1
        assert result.true_positives + result.false_negatives == 2


class TestEvaluateSeverityMatch:
    def test_severity_match_true(self, tmp_path):
        vulns = [_gt(id="V1", severity="high", category="misconfiguration")]
        findings = [_finding(id="F1", type="no_auth", severity="high")]
        run_dir = _write_run(tmp_path, findings)
        gt_file = _write_gt(tmp_path, vulns)

        result = evaluate(run_dir, gt_file)
        assert result.severity_mismatches == 0
        matched = [m for m in result.matches if m["matched"]]
        assert matched[0]["severity_match"] is True

    def test_severity_mismatch_counted(self, tmp_path):
        vulns = [_gt(id="V1", severity="critical", category="misconfiguration")]
        findings = [_finding(id="F1", type="no_auth", severity="low")]
        run_dir = _write_run(tmp_path, findings)
        gt_file = _write_gt(tmp_path, vulns)

        result = evaluate(run_dir, gt_file)
        assert result.severity_mismatches == 1
        matched = [m for m in result.matches if m["matched"]]
        assert matched[0]["severity_match"] is False


class TestEvaluateLooseMatchPenalty:
    def test_ip_type_match_full_weight(self, tmp_path):
        vulns = [_gt(id="V1", severity="high", category="misconfiguration", ip="192.168.100.11")]
        findings = [_finding(id="F1", ip="192.168.100.11", type="no_auth")]
        run_dir = _write_run(tmp_path, findings)
        gt_file = _write_gt(tmp_path, vulns, max_score=3)

        result = evaluate(run_dir, gt_file)
        assert result.weighted_score == 3.0  # full weight (high=3)

    def test_loose_match_half_weight(self, tmp_path):
        vulns = [_gt(id="V1", severity="high", category="misconfiguration", ip="192.168.100.11")]
        # type "unknown_type" forces ip+category fallback
        findings = [_finding(id="F1", ip="192.168.100.11", type="unknown_type")]
        run_dir = _write_run(tmp_path, findings)
        gt_file = _write_gt(tmp_path, vulns, max_score=3)

        result = evaluate(run_dir, gt_file)
        assert result.weighted_score == 1.5  # 0.5 * 3 (high)

    def test_cve_match_full_weight(self, tmp_path):
        vulns = [_gt(id="V1", severity="critical", category="cve",
                     cve="CVE-2023-48795", ip="192.168.100.14")]
        findings = [_finding(id="F1", ip="192.168.100.14", type="terrapin",
                             cve_ids=["CVE-2023-48795"], severity="critical")]
        run_dir = _write_run(tmp_path, findings)
        gt_file = _write_gt(tmp_path, vulns, max_score=4)

        result = evaluate(run_dir, gt_file)
        assert result.weighted_score == 4.0  # full weight (critical=4)


class TestEvaluateScorePct:
    def test_perfect_score(self, tmp_path):
        vulns = [_gt(id="V1", severity="high", category="misconfiguration")]
        findings = [_finding(id="F1", type="no_auth", severity="high")]
        run_dir = _write_run(tmp_path, findings)
        gt_file = _write_gt(tmp_path, vulns, max_score=3)

        result = evaluate(run_dir, gt_file)
        assert result.score_pct == 100.0

    def test_zero_score(self, tmp_path):
        vulns = [_gt(id="V1", severity="high")]
        findings = [_finding(id="F1", ip="192.168.100.99")]  # wrong IP → no match
        run_dir = _write_run(tmp_path, findings)
        gt_file = _write_gt(tmp_path, vulns, max_score=3)

        result = evaluate(run_dir, gt_file)
        assert result.score_pct == 0.0

    def test_partial_score_pct(self, tmp_path):
        vulns = [
            _gt(id="V1", severity="high", category="misconfiguration", ip="192.168.100.11"),
            _gt(id="V2", severity="high", category="misconfiguration", ip="192.168.100.12"),
        ]
        findings = [_finding(id="F1", ip="192.168.100.11", type="no_auth")]
        run_dir = _write_run(tmp_path, findings)
        gt_file = _write_gt(tmp_path, vulns, max_score=6)

        result = evaluate(run_dir, gt_file)
        # 1 match (high=3), max=6 → 50%
        assert result.score_pct == 50.0

    def test_score_pct_zero_when_no_max(self, tmp_path):
        run_dir = _write_run(tmp_path, [])
        gt_file = _write_gt(tmp_path, [], max_score=0)
        result = evaluate(run_dir, gt_file)
        assert result.score_pct == 0.0


class TestEvaluateBonusTypes:
    def test_bonus_not_counted_as_fp(self, tmp_path):
        vulns = [_gt(id="V1", severity="high", category="misconfiguration")]
        findings = [
            _finding(id="F1", ip="192.168.100.11", type="no_auth"),
            _finding(id="F2", ip="192.168.100.11", type="weak_cipher"),
            _finding(id="F3", ip="192.168.100.11", type="missing_header"),
        ]
        run_dir = _write_run(tmp_path, findings)
        gt_file = _write_gt(tmp_path, vulns, bonus_types=["weak_cipher", "missing_header"])

        result = evaluate(run_dir, gt_file)
        assert result.false_positives == 0
        assert result.bonus_findings == 2

    def test_non_bonus_type_counted_as_fp(self, tmp_path):
        vulns = [_gt(id="V1", severity="high", category="misconfiguration")]
        findings = [
            _finding(id="F1", ip="192.168.100.11", type="no_auth"),
            _finding(id="F2", ip="192.168.100.99", type="version_leak"),  # hallucination
        ]
        run_dir = _write_run(tmp_path, findings)
        gt_file = _write_gt(tmp_path, vulns, bonus_types=["weak_cipher"])

        result = evaluate(run_dir, gt_file)
        assert result.false_positives == 1
        assert result.bonus_findings == 0


class TestEvaluateMetrics:
    def test_perfect_recall_and_precision(self, tmp_path):
        vulns = [_gt(id="V1", category="misconfiguration", ip="192.168.100.11")]
        findings = [_finding(id="F1", ip="192.168.100.11", type="no_auth")]
        run_dir = _write_run(tmp_path, findings)
        gt_file = _write_gt(tmp_path, vulns)

        result = evaluate(run_dir, gt_file)
        assert result.recall == 1.0
        assert result.precision == 1.0
        assert result.f1_score == 1.0
        assert result.hallucination_rate == 0.0

    def test_all_missed(self, tmp_path):
        vulns = [_gt(id="V1", ip="192.168.100.11")]
        findings = [_finding(id="F1", ip="192.168.100.99")]
        run_dir = _write_run(tmp_path, findings)
        gt_file = _write_gt(tmp_path, vulns)

        result = evaluate(run_dir, gt_file)
        assert result.true_positives == 0
        assert result.false_negatives == 1
        assert result.false_positives == 1
        assert result.recall == 0.0
        assert result.precision == 0.0
        assert result.f1_score == 0.0
        assert result.hallucination_rate == 1.0

    def test_no_findings_no_fp(self, tmp_path):
        vulns = [_gt(id="V1")]
        run_dir = _write_run(tmp_path, [])
        gt_file = _write_gt(tmp_path, vulns)

        result = evaluate(run_dir, gt_file)
        assert result.false_positives == 0
        assert result.false_negatives == 1
        assert result.total_llm_findings == 0

    def test_detection_rate(self, tmp_path):
        vulns = [
            _gt(id="V1", ip="192.168.100.11", category="misconfiguration"),
            _gt(id="V2", ip="192.168.100.12", category="misconfiguration"),
            _gt(id="V3", ip="192.168.100.13", category="misconfiguration"),
        ]
        findings = [
            _finding(id="F1", ip="192.168.100.11", type="no_auth"),
            _finding(id="F2", ip="192.168.100.12", type="no_auth"),
        ]
        run_dir = _write_run(tmp_path, findings)
        gt_file = _write_gt(tmp_path, vulns)

        result = evaluate(run_dir, gt_file)
        assert result.detection_rate == pytest.approx(2 / 3, rel=1e-3)


class TestEvaluateMissingFile:
    def test_missing_vuln_file_raises(self, tmp_path):
        run_dir = tmp_path / "empty_run"
        run_dir.mkdir()
        gt_file = _write_gt(tmp_path, [])
        with pytest.raises(FileNotFoundError):
            evaluate(run_dir, gt_file)


class TestEvaluateCategories:
    """Ensure S4/S5 categories (no_authentication, code_injection) match correctly."""

    def test_no_authentication_matches_no_auth_finding(self, tmp_path):
        vulns = [_gt(id="V1", category="no_authentication", ip="192.168.100.15",
                     severity="critical")]
        findings = [_finding(id="F1", ip="192.168.100.15", type="no_auth",
                             severity="critical")]
        run_dir = _write_run(tmp_path, findings)
        gt_file = _write_gt(tmp_path, vulns, max_score=4)

        result = evaluate(run_dir, gt_file)
        assert result.true_positives == 1
        assert result.matches[0]["match_method"] == "ip+type"  # not loose

    def test_code_injection_matches_rce_finding(self, tmp_path):
        vulns = [_gt(id="V2", category="code_injection", ip="192.168.100.12",
                     severity="critical")]
        findings = [_finding(id="F1", ip="192.168.100.12", type="rce",
                             severity="critical")]
        run_dir = _write_run(tmp_path, findings)
        gt_file = _write_gt(tmp_path, vulns, max_score=4)

        result = evaluate(run_dir, gt_file)
        assert result.true_positives == 1
        assert result.matches[0]["match_method"] == "ip+type"
