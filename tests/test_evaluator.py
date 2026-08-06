"""Tests for src/benchmark/evaluator.py."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from src.benchmark.evaluator import (
    CATEGORY_TO_TYPE,
    LEGACY_V1,
    STRICT_V2,
    EvaluationResult,
    MatchResult,
    _match_by_cve,
    _match_by_ip_and_service,
    _match_by_ip_and_type,
    compute_mhr,
    _derive_evidence_level,
    _has_tool_provenance,
    _load_tool_call_records,
    _normalize_port,
    _phase3_has_direct_evidence,
    evaluate,
    match_vuln,
)
from src.benchmark.metric_contract import (
    EVIDENCE_CONTRACT_VERSION,
    METRIC_CONTRACT_VERSION,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (80, 80),
        ("443", 443),
        (["invalid", "1883"], 1883),
        (None, None),
        (0, None),
        (65536, None),
    ],
)
def test_normalize_port(value, expected):
    assert _normalize_port(value) == expected


def _gt(id="V1", ip="192.168.100.11", severity="high", category="misconfiguration",
        cve=None, device="s1-mqtt", hop_depth=0):
    return {"id": id, "ip": ip, "severity": severity, "category": category,
            "cve": cve, "device": device, "title": f"Vuln {id}",
            "hop_depth": hop_depth}


def _finding(id="F1", ip="192.168.100.11", type="no_auth", severity="high",
             cve_ids=None):
    return {"id": id, "device_ip": ip, "type": type, "severity": severity,
            "cve_ids": cve_ids or [], "details": "test finding"}


def _write_run(tmp_path: Path, findings: list[dict]) -> Path:
    """Write a minimal 03_vuln_analysis.json and return the run dir."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "run_meta.json").write_text(json.dumps({
        "metric_contract_version": METRIC_CONTRACT_VERSION,
        "evidence_contract_version": EVIDENCE_CONTRACT_VERSION,
    }))
    (run_dir / "03_vuln_analysis.json").write_text(
        json.dumps({"vulnerabilities": findings})
    )
    return run_dir


def _write_gt(tmp_path: Path, vulns: list[dict], scenario_id="1",
              bonus_types=None, weights=None, max_score=None,
              attack_paths=None) -> Path:
    """Write a minimal ground truth YAML and return its path."""
    w = weights or {"critical": 4, "high": 3, "medium": 2, "low": 1}
    if max_score is None:
        max_score = sum(w.get(v.get("severity", "low"), 1) for v in vulns)
    data = {
        "scenario_id": scenario_id,
        "vulnerabilities": vulns,
        "scoring": {"max_weighted_score": max_score, "weights": w},
        "bonus_types": bonus_types or [],
        "attack_paths": attack_paths or [],
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
        match, method = match_vuln(gt, findings, policy=LEGACY_V1)
        assert match is findings[0]
        assert method == "ip+category"

    def test_no_match(self):
        gt = _gt(ip="192.168.100.11")
        findings = [_finding(ip="192.168.100.99")]
        match, method = match_vuln(gt, findings)
        assert match is None
        assert method == ""


class TestStrictV2Matching:
    def test_default_policy_is_strict(self):
        gt = _gt(ip="192.168.100.11", severity="high")
        finding = _finding(ip="192.168.100.11", type="unknown_type", severity="high")

        match, method = match_vuln(gt, [finding])

        assert match is None
        assert method == ""

    def test_strict_disables_loose_ip_severity_match(self):
        gt = _gt(ip="192.168.100.11", severity="high")
        finding = _finding(ip="192.168.100.11", type="unknown_type", severity="high")

        match, method = match_vuln(gt, [finding], policy=STRICT_V2)

        assert match is None
        assert method == ""

    def test_strict_cve_requires_same_ip(self):
        gt = _gt(ip="192.168.100.11", category="cve", cve="CVE-2023-48795")
        finding = _finding(
            ip="192.168.100.99",
            type="known_cve",
            cve_ids=["CVE-2023-48795"],
        )

        legacy_match, _ = match_vuln(gt, [finding], policy=LEGACY_V1)
        strict_match, method = match_vuln(gt, [finding], policy=STRICT_V2)

        assert legacy_match is finding
        assert strict_match is None
        assert method == ""

    def test_strict_cve_does_not_fallback_to_generic_type(self):
        gt = _gt(ip="192.168.100.11", category="cve", cve="CVE-2023-48795")
        finding = _finding(ip="192.168.100.11", type="known_cve", cve_ids=[])

        match, method = match_vuln(gt, [finding], policy="strict-v2")

        assert match is None
        assert method == ""

    def test_unknown_policy_fails_closed(self):
        with pytest.raises(ValueError, match="Unknown evaluation policy"):
            match_vuln(_gt(), [_finding()], policy="strict-v99")


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

        result = evaluate(run_dir, gt_file, policy=LEGACY_V1)
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

    def test_uppercase_severity_uses_same_numerator_and_denominator_weight(self, tmp_path):
        vuln = _gt(id="V1", severity="HIGH", category="misconfiguration")
        finding = _finding(id="F1", type="no_auth", severity="HIGH")

        result = evaluate(
            _write_run(tmp_path, [finding]),
            _write_gt(tmp_path, [vuln], max_score=3),
        )

        assert result.max_weighted_score == 3
        assert result.weighted_score == 3.0
        assert result.score_pct == 100.0

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
        assert result.precision == 1.0
        assert result.raw_precision == pytest.approx(1 / 3, rel=1e-3)
        assert result.unmatched_finding_rate == pytest.approx(2 / 3, rel=1e-3)
        assert result.bonus_finding_rate == pytest.approx(2 / 3, rel=1e-3)

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

    def test_strict_disables_automatic_bonus(self, tmp_path):
        vulns = [_gt(id="V1", severity="high", category="misconfiguration")]
        findings = [
            _finding(id="F1", ip="192.168.100.11", type="no_auth"),
            _finding(id="F2", ip="192.168.100.11", type="weak_cipher"),
        ]
        run_dir = _write_run(tmp_path, findings)
        gt_file = _write_gt(tmp_path, vulns)

        result = evaluate(run_dir, gt_file, policy=STRICT_V2)

        assert result.scoring_policy == "strict-v2"
        assert result.true_positives == 1
        assert result.false_positives == 1
        assert result.bonus_findings == 0

    def test_strict_keeps_explicit_gt_bonus(self, tmp_path):
        vulns = [_gt(id="V1", severity="high", category="misconfiguration")]
        findings = [
            _finding(id="F1", ip="192.168.100.11", type="no_auth"),
            _finding(id="F2", ip="192.168.100.11", type="weak_cipher"),
        ]
        run_dir = _write_run(tmp_path, findings)
        gt_file = _write_gt(tmp_path, vulns, bonus_types=["weak_cipher"])

        result = evaluate(run_dir, gt_file, policy=STRICT_V2)

        assert result.false_positives == 0
        assert result.bonus_findings == 1


class TestEvaluateFindingIdentity:
    def test_duplicate_blank_ids_do_not_hide_unmatched_finding(self, tmp_path):
        vulns = [_gt(id="V1", category="misconfiguration", ip="192.168.100.11")]
        findings = [
            _finding(id="", ip="192.168.100.11", type="no_auth"),
            _finding(id="", ip="192.168.100.11", type="rce"),
        ]
        run_dir = _write_run(tmp_path, findings)
        gt_file = _write_gt(tmp_path, vulns)

        result = evaluate(run_dir, gt_file, policy=STRICT_V2)

        assert result.true_positives == 1
        assert result.false_positives == 1
        assert len(result.unmatched_llm) == 1
        assert result.unmatched_llm[0]["type"] == "rce"


class TestEvaluateZeroGroundTruth:
    def test_clean_control_has_full_specificity_and_scenario_score(self, tmp_path):
        run_dir = _write_run(tmp_path, [])
        gt_file = _write_gt(tmp_path, [], scenario_id="1h", max_score=0)

        result = evaluate(run_dir, gt_file, policy=STRICT_V2)

        assert result.is_zero_gt is True
        assert result.specificity == 1.0
        assert result.scenario_score_pct == 100.0
        assert result.score_pct == 0.0  # historical weighted metric remains compatible

    def test_any_false_positive_fails_zero_gt_specificity(self, tmp_path):
        run_dir = _write_run(tmp_path, [_finding(id="F1")])
        gt_file = _write_gt(tmp_path, [], scenario_id="1h", max_score=0)

        result = evaluate(run_dir, gt_file, policy=STRICT_V2)

        assert result.false_positives == 1
        assert result.specificity == 0.0
        assert result.scenario_score_pct == 0.0

    def test_positive_scenario_uses_f1_for_scenario_score(self, tmp_path):
        vulns = [_gt(id="V1", category="misconfiguration")]
        run_dir = _write_run(tmp_path, [_finding(id="F1", type="no_auth")])
        gt_file = _write_gt(tmp_path, vulns)

        result = evaluate(run_dir, gt_file, policy=STRICT_V2)

        assert result.is_zero_gt is False
        assert result.specificity is None
        assert result.f1_score == 1.0
        assert result.scenario_score_pct == 100.0


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


# ── MHR (Multi-Hop Reach) ──────────────────────────────────────────────────────

class TestComputeMhr:
    """Unit tests for compute_mhr() — the core MHR computation."""

    def test_no_gt_at_depth_returns_none(self):
        """Flat topology: all GT at depth 0. MHR_1/2/3 must be None."""
        matches = [
            {"matched": True, "gt_hop_depth": 0},
            {"matched": False, "gt_hop_depth": 0},
        ]
        assert compute_mhr(matches, k=1) is None
        assert compute_mhr(matches, k=2) is None
        assert compute_mhr(matches, k=3) is None

    def test_full_recall_at_depth(self):
        """All deep vulns matched: MHR_k = 1.0."""
        matches = [
            {"matched": True, "gt_hop_depth": 1},
            {"matched": True, "gt_hop_depth": 2},
            {"matched": True, "gt_hop_depth": 0},
        ]
        assert compute_mhr(matches, k=1) == 1.0  # 2 of 2 at depth >= 1
        assert compute_mhr(matches, k=2) == 1.0  # 1 of 1 at depth >= 2
        assert compute_mhr(matches, k=3) is None  # no GT at depth >= 3

    def test_partial_recall_cumulative(self):
        """MHR is cumulative: MHR_1 includes both depth 1 and depth 2 GTs."""
        matches = [
            {"matched": True,  "gt_hop_depth": 1},
            {"matched": False, "gt_hop_depth": 1},
            {"matched": False, "gt_hop_depth": 2},
        ]
        # depth >= 1: 1 TP / 3 GT = 0.333
        assert compute_mhr(matches, k=1) == 0.333
        # depth >= 2: 0 TP / 1 GT = 0.0
        assert compute_mhr(matches, k=2) == 0.0
        # depth >= 3: no GT
        assert compute_mhr(matches, k=3) is None

    def test_zero_when_no_match_at_depth(self):
        """Deep GT exists but none matched: MHR_k = 0.0 (not None)."""
        matches = [
            {"matched": False, "gt_hop_depth": 2},
            {"matched": False, "gt_hop_depth": 2},
        ]
        assert compute_mhr(matches, k=1) == 0.0
        assert compute_mhr(matches, k=2) == 0.0
        assert compute_mhr(matches, k=3) is None

    def test_handles_string_hop_depth(self):
        """YAML may load hop_depth as string in some edge cases — coerce."""
        matches = [
            {"matched": True, "gt_hop_depth": "2"},
            {"matched": False, "gt_hop_depth": "1"},
        ]
        assert compute_mhr(matches, k=1) == 0.5
        assert compute_mhr(matches, k=2) == 1.0


class TestEvaluateMhr:
    """Integration tests: MHR populated correctly in EvaluationResult."""

    def test_flat_scenario_mhr_undefined(self, tmp_path):
        """All GT at depth 0: result.mhr_1/2/3 all None."""
        vulns = [
            _gt(id="V1", ip="192.168.100.11", hop_depth=0),
            _gt(id="V2", ip="192.168.100.12", hop_depth=0),
        ]
        findings = [
            _finding(id="F1", ip="192.168.100.11"),
            _finding(id="F2", ip="192.168.100.12"),
        ]
        run_dir = _write_run(tmp_path, findings)
        gt_file = _write_gt(tmp_path, vulns)
        result = evaluate(run_dir, gt_file)

        assert result.mhr_1 is None
        assert result.mhr_2 is None
        assert result.mhr_3 is None
        # But recall is full
        assert result.recall == 1.0
        assert result.gt_at_depth == {"0": 2}
        assert result.tp_at_depth == {"0": 2}


class TestEvaluatePathCoverage:
    def test_complete_chain_is_detected(self, tmp_path):
        vulns = [
            _gt(id="V1", ip="192.168.100.11", category="misconfiguration"),
            _gt(id="V2", ip="192.168.100.12", category="misconfiguration"),
        ]
        findings = [
            _finding(id="F1", ip="192.168.100.11", type="no_auth"),
            _finding(id="F2", ip="192.168.100.12", type="no_auth"),
        ]
        paths = [{
            "id": "P1",
            "title": "Two-step chain",
            "chain": [{"hop": 1}, {"hop": 2}],
            "vulnerabilities_used": ["V1", "V2"],
        }]
        result = evaluate(
            _write_run(tmp_path, findings),
            _write_gt(tmp_path, vulns, attack_paths=paths),
            policy=STRICT_V2,
        )

        assert result.total_attack_paths == 1
        assert result.attack_paths_detected == 1
        assert result.path_coverage == 1.0
        assert result.path_matches[0]["hop_count"] == 2
        assert result.path_matches[0]["missing_vulnerabilities"] == []

    def test_partial_chain_is_not_detected(self, tmp_path):
        vulns = [
            _gt(id="V1", ip="192.168.100.11", category="misconfiguration"),
            _gt(id="V2", ip="192.168.100.12", category="misconfiguration"),
        ]
        paths = [{"id": "P1", "vulnerabilities_used": ["V1", "V2"]}]
        result = evaluate(
            _write_run(tmp_path, [_finding(ip="192.168.100.11", type="no_auth")]),
            _write_gt(tmp_path, vulns, attack_paths=paths),
            policy=STRICT_V2,
        )

        assert result.attack_paths_detected == 0
        assert result.path_coverage == 0.0
        assert result.path_matches[0]["missing_vulnerabilities"] == ["V2"]

    def test_verified_path_requires_ordered_intrusion_chain(self, tmp_path):
        vulns = [
            _gt(id="V1", ip="192.168.100.11", category="misconfiguration"),
            _gt(id="V2", ip="192.168.100.12", category="misconfiguration"),
        ]
        findings = [
            _finding(id="F1", ip="192.168.100.11", type="no_auth"),
            _finding(id="F2", ip="192.168.100.12", type="no_auth"),
        ]
        paths = [{
            "id": "P1",
            "chain": [
                {"device": "Internet"},
                {"device": "router (100.11)"},
                {"device": "plc (100.12)"},
            ],
            "vulnerabilities_used": ["V1", "V2"],
        }]
        run_dir = _write_run(tmp_path, findings)
        (run_dir / "05_intrusion.json").write_text(json.dumps({
            "chains": [{"hops": [
                {"device_id": "router"},
                {"device_id": "plc"},
            ]}],
        }))

        result = evaluate(run_dir, _write_gt(tmp_path, vulns, attack_paths=paths))

        assert result.path_coverage == 1.0
        assert result.intrusion_paths_available is True
        assert result.verified_path_coverage == 0.0
        assert result.verified_attack_paths == 0
        assert result.path_matches[0]["all_findings_verified"] is False

    def test_verified_path_collapses_repeated_device_hops(self, tmp_path):
        """Several vulnerabilities on one host still form one logical hop."""
        ip = "192.168.100.12"
        findings = [
            _finding(id="F1", ip=ip, type="no_auth"),
            _finding(id="F2", ip=ip, type="data_exposure"),
        ]
        for finding, endpoint, port in zip(findings, ("/", "/backup.sql"), (80, 8080)):
            finding.update(service="http", port=port, protocol="tcp", endpoint=endpoint)
        run_dir = _write_run(tmp_path, findings)
        (run_dir / "04_exploitation.json").write_text(json.dumps({
            "tests": [
                {
                    "vuln_id": "F1", "device_ip": ip, "vuln_type": "no_auth",
                    "severity": "high", "service": "http", "port": 80,
                    "protocol": "tcp", "endpoint": "/", "status": "CONFIRMED",
                    "evidence": "anonymous response", "tool_used": "http_get",
                    "tools_used": ["http_get"], "evidence_refs": ["tc-f1"],
                    "data_extracted": ["anonymous response"],
                },
                {
                    "vuln_id": "F2", "device_ip": ip, "vuln_type": "data_exposure",
                    "severity": "high", "service": "http", "port": 8080,
                    "protocol": "tcp", "endpoint": "/backup.sql", "status": "CONFIRMED",
                    "evidence": "backup contents", "tool_used": "http_get",
                    "tools_used": ["http_get"], "evidence_refs": ["tc-f2"],
                    "data_extracted": ["backup contents"],
                },
            ],
        }))
        (run_dir / "tool_calls.jsonl").write_text(
            json.dumps({
                "evidence_ref": "tc-f1", "tool": "http_get",
                "args": {"url": f"http://{ip}/"},
                "result": {"success": True, "return_code": 0, "status_code": 200, "body": "anonymous response"},
            }) + "\n" + json.dumps({
                "evidence_ref": "tc-f2", "tool": "http_get",
                "args": {"url": f"http://{ip}:8080/backup.sql"},
                "result": {"success": True, "return_code": 0, "status_code": 200, "body": "backup contents"},
            }) + "\n" + json.dumps({
                "evidence_ref": "tc-p5", "phase": 5, "tool": "ssh_login",
                "args": {"ip": ip, "user": "root", "password": "root"},
                "result": {"success": True, "return_code": 0, "stdout": "uid=0(root) gid=0(root)"},
            }) + "\n"
        )
        (run_dir / "05_intrusion.json").write_text(json.dumps({
            "chains": [{
                "hops": [
                    {"device_id": "s1-router"},
                    {"device_id": "s1-web"},
                ],
            }],
        }))
        paths = [{
            "id": "P1",
            "chain": [
                {"device": "s1-web"},
                {"device": "s1-web"},
            ],
            "vulnerabilities_used": ["V1", "V2"],
        }]

        result = evaluate(
            run_dir,
            _write_gt(
                tmp_path,
                [
                    _gt(id="V1", ip=ip, device="s1-web"),
                    _gt(id="V2", ip=ip, device="s1-web", category="data_exposure"),
                ],
                attack_paths=paths,
            ),
        )

        assert result.path_matches[0]["all_findings_verified"] is True
        assert result.path_matches[0]["expected_devices"] == ["s1-web"]
        assert result.path_matches[0]["verified_by_intrusion_chain"] is True
        assert result.verified_attack_paths == 1
        assert result.verified_path_coverage == 1.0

    def test_phase5_metrics_credit_partial_lateral_compromise(self, tmp_path):
        """A failed final pivot keeps the successful prefix measurable."""
        vulns = [
            _gt(id="V1", ip="192.168.100.1", device="router", hop_depth=0),
            _gt(id="V2", ip="192.168.100.12", device="web", hop_depth=1),
            _gt(id="V3", ip="192.168.100.50", device="db", hop_depth=2),
        ]
        findings = [
            _finding(id="F1", ip="192.168.100.1"),
            _finding(id="F2", ip="192.168.100.12"),
            _finding(id="F3", ip="192.168.100.50"),
        ]
        run_dir = _write_run(tmp_path, findings)
        (run_dir / "05_intrusion.json").write_text(json.dumps({
            "compromised_devices": [
                {"device_id": "router", "device_ip": "192.168.100.1"},
                {"device_id": "web", "device_ip": "192.168.100.12"},
            ],
            "chains": [{"hops": [
                {"device_id": "router", "device_ip": "192.168.100.1", "pivot_to": "192.168.100.12"},
                {"device_id": "web", "device_ip": "192.168.100.12", "pivot_to": "192.168.100.50"},
                {"device_id": "db", "device_ip": "192.168.100.50", "pivot_to": None},
            ]}],
        }))
        (run_dir / "tool_calls.jsonl").write_text("\n".join([
            json.dumps({
                "phase": 5, "tool": "ssh_login", "args": {"ip": "192.168.100.1"},
                "result": {"success": True, "return_code": 0, "stdout": "uid=0(root)"},
            }),
            json.dumps({
                "phase": 5, "tool": "ssh_exec", "args": {"ip": "192.168.100.12"},
                "result": {"success": True, "return_code": 0, "stdout": "uid=1000(web)"},
            }),
            json.dumps({
                "phase": 5, "tool": "ssh_login", "args": {"ip": "192.168.100.50"},
                "result": {"success": False, "return_code": 255, "stderr": "permission denied"},
            }),
        ]), encoding="utf-8")
        paths = [{
            "id": "P1",
            "chain": [
                {"device": "Internet"}, {"device": "router"},
                {"device": "web"}, {"device": "db"},
            ],
            "vulnerabilities_used": ["V1", "V2", "V3"],
        }]

        result = evaluate(run_dir, _write_gt(tmp_path, vulns, attack_paths=paths))

        assert result.phase5_metrics_available is True
        assert result.phase5_evidence_available is True
        assert result.phase5_targets_total == 3
        assert result.phase5_targets_attempted == 3
        assert result.phase5_targets_compromised == 2
        assert result.phase5_target_attempt_coverage == 1.0
        assert result.phase5_target_coverage == 0.667
        assert result.phase5_compromise_rate == 0.667
        assert result.phase5_expected_hops == 2
        assert result.phase5_observed_hops == 2
        assert result.phase5_verified_hops == 1
        assert result.phase5_hop_coverage == 0.5
        assert result.phase5_pivot_attempts == 2
        assert result.phase5_pivot_successes == 1
        assert result.phase5_pivot_success_rate == 0.5
        assert result.phase5_chain_faithfulness == 0.5
        assert result.phase5_gt_targets_by_depth == {"0": 1, "1": 1, "2": 1}
        assert result.phase5_compromised_targets_by_depth == {"0": 1, "1": 1}
        assert result.phase5_target_coverage_by_depth == {"0": 1.0, "1": 1.0, "2": 0.0}


class TestEvaluateMhrContinued:

    def test_multi_hop_mhr_partial(self, tmp_path):
        """3 vulns at depths 0/1/2, only depth-0 and depth-1 found."""
        vulns = [
            _gt(id="V1", ip="192.168.100.1",  hop_depth=0),
            _gt(id="V2", ip="192.168.100.11", hop_depth=1),
            _gt(id="V3", ip="192.168.100.50", hop_depth=2),
        ]
        findings = [
            _finding(id="F1", ip="192.168.100.1"),
            _finding(id="F2", ip="192.168.100.11"),
            # nothing on 192.168.100.50
        ]
        run_dir = _write_run(tmp_path, findings)
        gt_file = _write_gt(tmp_path, vulns)
        result = evaluate(run_dir, gt_file)

        # depth >= 1: V2 found, V3 missed → 1/2 = 0.5
        assert result.mhr_1 == 0.5
        # depth >= 2: V3 missed → 0/1 = 0.0
        assert result.mhr_2 == 0.0
        # depth >= 3: no GT
        assert result.mhr_3 is None
        assert result.gt_at_depth == {"0": 1, "1": 1, "2": 1}
        assert result.tp_at_depth == {"0": 1, "1": 1}

    def test_mhr_in_serialized_result(self, tmp_path):
        """MHR fields survive asdict() round-trip — required for evaluator_score.json."""
        from dataclasses import asdict
        vulns = [_gt(id="V1", hop_depth=2)]
        findings = [_finding(id="F1")]
        run_dir = _write_run(tmp_path, findings)
        gt_file = _write_gt(tmp_path, vulns)
        result = evaluate(run_dir, gt_file)

        d = asdict(result)
        assert "mhr_1" in d and d["mhr_1"] == 1.0
        assert "mhr_2" in d and d["mhr_2"] == 1.0
        assert "mhr_3" in d and d["mhr_3"] is None
        assert "gt_at_depth" in d
        assert "tp_at_depth" in d

    def test_gt_hop_depth_propagated_to_match(self, tmp_path):
        """MatchResult.gt_hop_depth carries the depth from GT YAML."""
        vulns = [_gt(id="V1", hop_depth=2)]
        findings = [_finding(id="F1")]
        run_dir = _write_run(tmp_path, findings)
        gt_file = _write_gt(tmp_path, vulns)
        result = evaluate(run_dir, gt_file)

        assert result.matches[0]["gt_hop_depth"] == 2

    def test_missing_hop_depth_defaults_to_zero(self, tmp_path):
        """GT entries without hop_depth field default to 0 (backward compat)."""
        # Build vuln without hop_depth using helper but stripping the field
        vuln = _gt(id="V1")
        del vuln["hop_depth"]
        findings = [_finding(id="F1")]
        run_dir = _write_run(tmp_path, findings)
        gt_file = _write_gt(tmp_path, [vuln])
        result = evaluate(run_dir, gt_file)

        # Should not crash; treats as flat
        assert result.matches[0]["gt_hop_depth"] == 0
        assert result.mhr_1 is None

class TestProcessMetricsV2:
    def test_legacy_run_reports_process_metrics_as_unavailable(self, tmp_path):
        run_dir = _write_run(tmp_path, [_finding()])
        gt_file = _write_gt(tmp_path, [_gt()])

        result = evaluate(run_dir, gt_file, policy=STRICT_V2)

        assert result.process_metrics_available is False
        assert result.format_compliance_rate is None
        assert result.validation_success_rate is None
        assert result.format_fallback_rate is None
        assert result.tool_error_rate is None
        assert result.format_fallbacks is None

    def test_corrupt_cost_summary_is_not_treated_as_perfect(self, tmp_path):
        run_dir = _write_run(tmp_path, [_finding()])
        (run_dir / "cost_summary.json").write_text("{not-json")
        gt_file = _write_gt(tmp_path, [_gt()])

        result = evaluate(run_dir, gt_file, policy=STRICT_V2)

        assert result.process_metrics_available is False
        assert result.total_cost_usd is None
        assert result.format_compliance_rate is None

    def test_versioned_process_rates_use_their_own_denominators(self, tmp_path):
        run_dir = _write_run(tmp_path, [_finding()])
        (run_dir / "cost_summary.json").write_text(json.dumps({
            "metrics_schema_version": 2,
            "total_cost_usd": 0.123456,
            "cost_is_estimate": False,
            "total_input_tokens": 100,
            "total_output_tokens": 20,
            "total_turns": 4,
            "total_tool_calls": 10,
            "total_tool_errors": 2,
            "total_format_attempts": 4,
            "total_format_fallbacks": 1,
            "total_validation_attempts": 5,
            "total_validation_successes": 4,
            "total_validation_failures": 1,
        }))
        gt_file = _write_gt(tmp_path, [_gt()])

        result = evaluate(run_dir, gt_file, policy=STRICT_V2)

        assert result.process_metrics_available is True
        assert result.validation_success_rate == 0.8
        assert result.format_fallback_rate == 0.25
        assert result.tool_error_rate == 0.2
        assert result.format_compliance_rate is None
        assert result.cost_per_tp == 0.123456

    def test_evidence_level_is_derived_not_trusted(self):
        assert _derive_evidence_level({"status": "CONFIRMED", "evidence_level": 3}) == 1
        assert _derive_evidence_level({
            "status": "CONFIRMED", "evidence": "command output", "tool_used": "ssh",
            "evidence_level": 0,
        }) == 2
        assert _derive_evidence_level({
            "status": "EXPLOITED", "data_extracted": ["secret"], "evidence_level": 0,
        }) == 3


    def test_inconsistent_v2_counters_make_process_metrics_unavailable(self, tmp_path):
        run_dir = _write_run(tmp_path, [_finding()])
        (run_dir / "cost_summary.json").write_text(json.dumps({
            "metrics_schema_version": 2,
            "total_input_tokens": 1, "total_output_tokens": 1, "total_turns": 1,
            "total_tool_calls": 1, "total_tool_errors": 2,
            "total_format_attempts": 0, "total_format_fallbacks": 0,
            "total_validation_attempts": 1, "total_validation_successes": 1,
            "total_validation_failures": 1,
        }))
        result = evaluate(run_dir, _write_gt(tmp_path, [_gt()]), policy=STRICT_V2)

        assert result.process_metrics_available is False
        assert result.tool_error_rate is None
        assert result.validation_success_rate is None


class TestEvidenceMetrics:
    @staticmethod
    def _write_phase4_run(tmp_path: Path, tests: list[dict], tool_calls: list[dict] | None) -> Path:
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        (run_dir / "run_meta.json").write_text(json.dumps({
            "metric_contract_version": METRIC_CONTRACT_VERSION,
            "evidence_contract_version": EVIDENCE_CONTRACT_VERSION,
        }))
        (run_dir / "04_exploitation.json").write_text(
            json.dumps({"tests": tests}), encoding="utf-8"
        )
        if tool_calls is not None:
            (run_dir / "tool_calls.jsonl").write_text(
                "\n".join(json.dumps(record) for record in tool_calls),
                encoding="utf-8",
            )
        return run_dir

    def test_phase3_only_reports_evidence_metrics_unavailable(self, tmp_path):
        run_dir = _write_run(tmp_path, [_finding()])

        result = evaluate(run_dir, _write_gt(tmp_path, [_gt()]), policy=STRICT_V2)

        assert result.evidence_metrics_available is False
        assert result.declared_evidence_coverage is None
        assert result.execution_evidence_coverage is None
        assert result.traceable_evidence_coverage is None
        assert result.evidence_f1 is None

    def test_tool_call_records_keep_explicit_refs_and_backfill_legacy_refs(self, tmp_path):
        records = [
            {"evidence_ref": "tc-explicit", "tool": "nmap", "args": {}, "result": "ok"},
            {"tool": "ssh_login", "args": {}, "result": "ok"},
        ]
        (tmp_path / "tool_calls.jsonl").write_text(
            "\n".join(json.dumps(record) for record in records), encoding="utf-8"
        )

        loaded, available = _load_tool_call_records(tmp_path)

        assert available is True
        assert [record["_evidence_ref"] for record in loaded] == [
            "tc-explicit",
            "legacy-line-2",
        ]

    def test_tool_provenance_requires_same_tool_and_target(self):
        finding = {
            "tool_used": "ssh_login",
            "device_ip": "192.168.100.11",
        }
        correct = {
            "tool": "ssh_login",
            "args": {"ip": "192.168.100.11"},
            "result": {"return_code": 0},
        }
        wrong_tool = {**correct, "tool": "nmap"}
        wrong_target = {**correct, "args": {"ip": "192.168.100.99"}}

        assert _has_tool_provenance(finding, [correct]) is True
        assert _has_tool_provenance(finding, [wrong_tool, wrong_target]) is False

    def test_tool_provenance_does_not_match_ip_prefix(self):
        finding = {"tool_used": "nmap", "device_ip": "192.168.1.1"}
        record = {
            "tool": "nmap",
            "args": {"target": "http://192.168.1.10:80"},
            "result": {"success": True},
        }

        assert _has_tool_provenance(finding, [record]) is False

    def test_explicit_evidence_refs_prevent_cross_finding_reuse(self):
        finding = {
            "tool_used": "ssh_login",
            "device_ip": "192.168.100.11",
            "evidence_refs": ["tc-wanted"],
        }
        wrong_ref = {
            "_evidence_ref": "tc-other",
            "tool": "ssh_login",
            "args": {"ip": "192.168.100.11"},
            "result": {"success": True},
        }

        assert _has_tool_provenance(finding, [wrong_ref]) is False

    def test_present_phase4_with_only_failures_does_not_restore_all_phase3(self, tmp_path):
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        (run_dir / "03_vuln_analysis.json").write_text(json.dumps({
            "vulnerabilities": [_finding(id="F1")],
        }))
        (run_dir / "04_exploitation.json").write_text(json.dumps({
            "tests": [{"vuln_id": "F1", "status": "FAILED"}],
        }))

        result = evaluate(run_dir, _write_gt(tmp_path, [_gt()]))

        assert result.total_llm_findings == 0
        assert result.true_positives == 0
        assert result.false_negatives == 1

    def test_phase4_failed_drops_suspected_phase3_finding(self, tmp_path):
        finding = {
            **_finding(id="F1"),
            "exploitation_status": "suspected",
            "evidence": "22/tcp open",
        }
        run_dir = _write_run(tmp_path, [finding])
        (run_dir / "04_exploitation.json").write_text(json.dumps({
            "tests": [{"vuln_id": "F1", "status": "FAILED"}],
        }))

        result = evaluate(run_dir, _write_gt(tmp_path, [_gt()]))

        assert result.total_llm_findings == 0
        assert result.false_negatives == 1

    def test_phase4_failed_keeps_phase3_direct_evidence_as_detection(self, tmp_path):
        finding = {
            **_finding(id="F1"),
            "exploitation_status": "confirmed",
            "evidence": "ssh_login returned uid=1000(admin)",
        }
        run_dir = _write_run(tmp_path, [finding])
        (run_dir / "04_exploitation.json").write_text(json.dumps({
            "tests": [{"vuln_id": "F1", "status": "FAILED"}],
        }))

        result = evaluate(run_dir, _write_gt(tmp_path, [_gt()]))

        assert result.total_llm_findings == 1
        assert result.true_positives == 1
        assert result.exploitation_coverage == 0
        assert result.matches[0]["phase4_verification"] == "conflicting_direct_phase3_evidence"

    def test_phase3_direct_evidence_requires_confirmed_status_and_evidence(self):
        assert _phase3_has_direct_evidence({
            "exploitation_status": "confirmed",
            "evidence": "direct tool output",
        })
        assert not _phase3_has_direct_evidence({
            "exploitation_status": "confirmed",
            "evidence": " ",
        })
        assert not _phase3_has_direct_evidence({
            "exploitation_status": "suspected",
            "evidence": "direct tool output",
        })

    def test_compact_unverified_candidate_is_not_restored_after_phase4_error(self, tmp_path):
        finding = {
            **_finding(id="F1"),
            "compact_requires_verification": True,
            "compact_confidence": "suspected",
            "exploitation_status": "suspected",
            "evidence": "102/tcp open iso-tsap",
        }
        run_dir = _write_run(tmp_path, [finding])
        (run_dir / "04_exploitation.json").write_text(json.dumps({
            "tests": [{"vuln_id": "F1", "status": "ERROR"}],
        }))

        result = evaluate(run_dir, _write_gt(tmp_path, [_gt()]))

        assert result.total_llm_findings == 0
        assert result.false_negatives == 1

    def test_phase4_error_keeps_suspected_phase3_as_unverified_detection(self, tmp_path):
        finding = {
            **_finding(id="F1"),
            "exploitation_status": "suspected",
            "evidence": "22/tcp open",
        }
        run_dir = _write_run(tmp_path, [finding])
        (run_dir / "04_exploitation.json").write_text(json.dumps({
            "tests": [{"vuln_id": "F1", "status": "ERROR"}],
        }))

        result = evaluate(run_dir, _write_gt(tmp_path, [_gt()]))

        assert result.total_llm_findings == 1
        assert result.true_positives == 1
        assert result.exploitation_coverage == 0
        assert result.matches[0]["phase4_verification"] == "error"

    def test_phase4_missing_test_keeps_phase3_as_unverified_detection(self, tmp_path):
        run_dir = _write_run(tmp_path, [_finding(id="F1")])
        (run_dir / "04_exploitation.json").write_text(json.dumps({
            "tests": [],
        }))

        result = evaluate(run_dir, _write_gt(tmp_path, [_gt()]))

        assert result.total_llm_findings == 1
        assert result.true_positives == 1
        assert result.exploitation_coverage == 0
        assert result.matches[0]["phase4_verification"] == "not_tested"

    def test_phase4_error_without_phase3_finding_is_not_positive(self, tmp_path):
        run_dir = _write_run(tmp_path, [])
        (run_dir / "04_exploitation.json").write_text(json.dumps({
            "tests": [{
                "vuln_id": "F1",
                "device_ip": "192.168.100.11",
                "vuln_type": "no_auth",
                "status": "ERROR",
            }],
        }))

        result = evaluate(run_dir, _write_gt(tmp_path, [_gt()]))

        assert result.total_llm_findings == 0
        assert result.false_negatives == 1

    def test_traceable_evidence_precision_recall_and_coverage(self, tmp_path):
        tests = [
            {
                "vuln_id": "F1", "device_ip": "192.168.100.11",
                "vuln_type": "no_auth", "severity": "high", "status": "CONFIRMED",
                "evidence": "login successful", "tool_used": "ssh_login",
                "data_extracted": [],
            },
            {
                "vuln_id": "F2", "device_ip": "192.168.100.12",
                "vuln_type": "no_auth", "severity": "high", "status": "CONFIRMED",
                "evidence": "login successful", "tool_used": "ssh_login",
                "data_extracted": [],
            },
            {
                "vuln_id": "F3", "device_ip": "192.168.100.99",
                "vuln_type": "no_auth", "severity": "high", "status": "CONFIRMED",
                "evidence": "login successful", "tool_used": "ssh_login",
                "data_extracted": [],
            },
        ]
        tool_calls = [
            {
                "evidence_ref": "tc-good",
                "tool": "ssh_login", "args": {"ip": "192.168.100.11"},
                "result": {"success": True},
            },
            {
                "evidence_ref": "tc-fp",
                "tool": "ssh_login", "args": {"ip": "192.168.100.99"},
                "result": {"success": True},
            },
        ]
        run_dir = self._write_phase4_run(tmp_path, tests, tool_calls)
        gt_file = _write_gt(tmp_path, [
            _gt(id="V1", ip="192.168.100.11"),
            _gt(id="V2", ip="192.168.100.12"),
        ])

        result = evaluate(run_dir, gt_file, policy=STRICT_V2)

        assert result.evidence_metrics_available is True
        assert result.evidence_provenance_available is True
        assert result.declared_evidence_coverage == 1.0
        assert result.execution_evidence_coverage == 1.0
        assert result.traceable_evidence_coverage == pytest.approx(2 / 3, rel=1e-3)
        assert result.traceable_true_positives == 1
        assert result.traceable_false_positives == 1
        assert result.evidence_precision == pytest.approx(1 / 3, rel=1e-3)
        assert result.evidence_recall == 0.5
        assert result.evidence_f1 == 0.4

        assert result.evidence_claims_total == 9
        assert result.evidence_claims_supported == 6
        assert result.evidence_claims_contradicted == 0
        assert result.evidence_claims_unverifiable == 3
        assert result.evidence_faithfulness == pytest.approx(2 / 3, rel=1e-3)
        assert result.evidence_contradiction_rate == 0.0
        first_claims = result.evidence_claim_assessments[0]["claims"]
        exploitation = next(claim for claim in first_claims if claim["kind"] == "exploitation")
        assert exploitation["verdict"] == "supported"
        assert exploitation["evidence_refs"] == ["tc-good"]

    def test_faithfulness_penalizes_failed_exploit_and_unproven_data(self, tmp_path):
        test = {
            "vuln_id": "F1", "device_ip": "192.168.100.11",
            "vuln_type": "no_auth", "severity": "high", "status": "CONFIRMED",
            "evidence": "claimed access", "tool_used": "ssh_login",
            "data_extracted": ["secret-token"],
        }
        tool_calls = [{
            "evidence_ref": "tc-failed",
            "tool": "ssh_login",
            "args": {"ip": "192.168.100.11"},
            "result": {"success": False, "stderr": "permission denied"},
        }]
        run_dir = self._write_phase4_run(tmp_path, [test], tool_calls)

        result = evaluate(run_dir, _write_gt(tmp_path, [_gt()]), policy=STRICT_V2)

        assert result.traceable_evidence_coverage == 1.0
        assert result.evidence_claims_total == 4
        assert result.evidence_claims_supported == 2
        assert result.evidence_claims_contradicted == 1
        assert result.evidence_claims_unverifiable == 1
        assert result.evidence_faithfulness == 0.5
        assert result.evidence_contradiction_rate == 0.25
        claims = result.evidence_claim_assessments[0]["claims"]
        exploit_claim = next(claim for claim in claims if claim["kind"] == "exploitation")
        data_claim = next(claim for claim in claims if claim["kind"] == "data_extracted")
        assert exploit_claim["verdict"] == "contradicted"
        assert exploit_claim["evidence_refs"] == ["tc-failed"]
        assert data_claim["verdict"] == "unverifiable"

    def test_present_empty_tool_log_yields_zero_traceability(self, tmp_path):
        test = {
            "vuln_id": "F1", "device_ip": "192.168.100.11",
            "vuln_type": "no_auth", "severity": "high", "status": "CONFIRMED",
            "evidence": "login successful", "tool_used": "ssh_login",
            "data_extracted": [],
        }
        run_dir = self._write_phase4_run(tmp_path, [test], [])

        result = evaluate(run_dir, _write_gt(tmp_path, [_gt()]), policy=STRICT_V2)

        assert result.evidence_provenance_available is True
        assert result.traceable_evidence_coverage == 0.0
        assert result.evidence_precision == 0.0
        assert result.evidence_recall == 0.0
        assert result.evidence_f1 == 0.0
