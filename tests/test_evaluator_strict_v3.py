"""Strict-v3 evaluator contract tests."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

from src.benchmark.evaluator import (
    STRICT_V3,
    _tool_call_outcome,
    evaluate,
    match_vuln,
)
from src.benchmark.strict_v3 import cve_is_allowed


def _gt(**overrides):
    value = {
        "id": "V1",
        "title": "Public backup exposes credentials",
        "device": "web",
        "ip": "192.0.2.10",
        "severity": "high",
        "category": "data_exposure",
        "cve": None,
        "accepted_types": ["data_exposure"],
        "services": ["http"],
        "ports": [80],
        "protocols": ["tcp"],
        "endpoints": ["/backup.sql"],
        "products": [],
        "hop_depth": 0,
    }
    value.update(overrides)
    return value


def _finding(**overrides):
    value = {
        "id": "F1",
        "device_ip": "192.0.2.10",
        "type": "data_exposure",
        "severity": "high",
        "service": "http",
        "port": 80,
        "protocol": "tcp",
        "endpoint": "/backup.sql",
        "evidence": "GET /backup.sql returned credentials",
        "exploitation_status": "confirmed",
        "cve_ids": [],
    }
    value.update(overrides)
    return value


def _write(tmp_path: Path, findings, vulnerabilities=None, *, controls=None, bonus_types=None):
    run = tmp_path / "run"
    run.mkdir()
    (run / "03_vuln_analysis.json").write_text(json.dumps({"vulnerabilities": findings}))
    gt = tmp_path / "gt.yaml"
    vulns = vulnerabilities if vulnerabilities is not None else [_gt()]
    gt.write_text(yaml.safe_dump({
        "scenario_id": "test",
        "vulnerabilities": vulns,
        "controls": controls or [],
        "attack_paths": [],
        "bonus_types": bonus_types or [],
        "scoring": {
            "weights": {"critical": 4, "high": 3, "medium": 2, "low": 1},
            "max_bonus_findings": 1,
        },
    }))
    return run, gt


def test_public_matching_catalog_covers_every_ground_truth_entry():
    root = Path(__file__).resolve().parents[1] / "benchmarks" / "ground_truth"
    catalog = yaml.safe_load((root / "matching_contracts.yaml").read_text())
    assert catalog["schema_version"] == "strict-v3.2"
    for path in root.glob("scenario_*.yaml"):
        ground_truth = yaml.safe_load(path.read_text()) or {}
        scenario_id = str(ground_truth.get("scenario_id"))
        contracts = catalog["scenarios"][scenario_id]
        assert catalog["source_hashes"][scenario_id] == hashlib.sha256(path.read_bytes()).hexdigest()
        assert set(contracts) == {
            str(vulnerability["id"])
            for vulnerability in ground_truth.get("vulnerabilities", [])
        }
        assert all(contract["accepted_types"] for contract in contracts.values())


def test_rejects_broad_category_substitution():
    finding = _finding(type="missing_header")
    match, method = match_vuln(_gt(), [finding], policy=STRICT_V3)
    assert match is None
    assert method == ""


def test_rejects_conflicting_service_or_port():
    finding = _finding(service="mqtt", port=1883)
    match, _ = match_vuln(_gt(), [finding], policy=STRICT_V3)
    assert match is None


def test_exact_structure_gets_full_match_credit_but_detection_only_proof_credit(tmp_path):
    run, gt = _write(tmp_path, [_finding()])
    result = evaluate(run, gt, policy=STRICT_V3)
    assert result.detection_f1 == 1.0
    assert result.credited_f1 == 1.0
    assert result.matches[0]["match_credit"] == 1.0
    assert result.matches[0]["structural_match"] is True
    assert result.matches[0]["verification_credit"] == 0.5
    assert result.scenario_score_pct == 50.0


def test_missing_structure_gets_partial_credit(tmp_path):
    finding = _finding(service="", port=None, protocol="", endpoint="")
    run, gt = _write(tmp_path, [finding])
    result = evaluate(run, gt, policy=STRICT_V3)
    assert result.detection_f1 == 1.0
    assert result.credited_f1 == 0.75
    assert result.matches[0]["match_credit"] == 0.75
    assert result.scenario_score_pct == 37.5


def test_primary_score_includes_severity_error(tmp_path):
    run, gt = _write(tmp_path, [_finding(severity="low")], [_gt(severity="critical")])
    result = evaluate(run, gt, policy=STRICT_V3)
    assert result.detection_f1 == 1.0
    assert result.severity_adjusted_f1 == 0.25
    assert result.scenario_score_pct == 12.5


def test_verified_f1_requires_successful_linked_tool_call(tmp_path):
    run, gt = _write(tmp_path, [_finding()])
    (run / "04_exploitation.json").write_text(json.dumps({"tests": [{
        "vuln_id": "F1", "device_ip": "192.0.2.10", "vuln_type": "data_exposure",
        "severity": "high", "service": "http", "port": 80,
        "protocol": "tcp", "endpoint": "/backup.sql", "status": "CONFIRMED",
        "evidence": "credentials returned", "tool_used": "http_get",
    }]}))
    (run / "tool_calls.jsonl").write_text(json.dumps({
        "tool": "http_get", "args": {"url": "http://192.0.2.10/backup.sql"},
        "result": {"success": True, "body": "password=secret"},
    }) + "\n")
    result = evaluate(run, gt, policy=STRICT_V3)
    assert result.verified_f1 == 1.0
    assert result.matches[0]["verification_credit"] == 1.0
    assert result.scenario_score_pct == 100.0
    assert result.phase4_completion_rate == 1.0


def test_mqtt_rc27_with_payload_is_positive_tool_evidence():
    record = {
        "tool": "mqtt_listen",
        "args": {"broker": "192.0.2.11", "topic": "#"},
        "result": json.dumps({
            "stdout": "smartcity/admin/credentials {\"db_pass\":\"secret\"}",
            "stderr": "Timed out\n",
            "return_code": 27,
        }),
    }

    assert _tool_call_outcome(
        record, _finding(type="no_auth", service="mqtt", port=1883)
    ) is True


def test_phase4_error_is_incomplete(tmp_path):
    run, gt = _write(tmp_path, [_finding(exploitation_status="suspected")])
    (run / "04_exploitation.json").write_text(json.dumps({
        "tests": [{"vuln_id": "F1", "status": "ERROR"}],
    }))
    result = evaluate(run, gt, policy=STRICT_V3)
    assert result.phase4_candidates == 1
    assert result.phase4_conclusive == 0
    assert result.phase4_completion_rate == 0.0


def test_negative_control_violation_reduces_primary_score(tmp_path):
    control = {
        "id": "C1", "ip": "192.0.2.20", "assertion": "anonymous_mqtt_denied",
    }
    findings = [_finding(), _finding(id="F2", device_ip="192.0.2.20", type="no_auth")]
    run, gt = _write(tmp_path, findings, controls=[control])
    result = evaluate(run, gt, policy=STRICT_V3)
    assert result.negative_control_violations == 1
    assert result.negative_control_specificity == 0.0
    assert result.negative_control_penalty_factor == 0.8
    assert result.scenario_score_pct == 26.6


def test_unknown_cve_is_reported_and_cannot_match_cve_gt(tmp_path):
    vulnerability = _gt(
        category="cve", cve="CVE-2099-9999", accepted_types=["known_cve"],
        products=["imaginary"],
    )
    finding = _finding(type="known_cve", cve_ids=["CVE-2099-9999"])
    run, gt = _write(tmp_path, [finding], [vulnerability])
    result = evaluate(run, gt, policy=STRICT_V3)
    assert result.malformed_cve_claims == 1
    assert result.invalid_cve_claims == 1
    assert result.true_positives == 0


def test_known_cve_requires_expected_product_and_version_context():
    vulnerability = _gt(
        category="cve", cve="CVE-2023-48795",
        accepted_types=["known_cve", "terrapin"],
        products=["dropbear"], versions=["2020.81"],
    )
    bare = _finding(type="known_cve", cve_ids=["CVE-2023-48795"], evidence="ssh issue")
    supported = _finding(
        type="known_cve", cve_ids=["CVE-2023-48795"],
        evidence="ssh-audit identifies Dropbear 2020.81 as affected by Terrapin",
    )
    assert match_vuln(vulnerability, [bare], policy=STRICT_V3)[0] is None
    assert match_vuln(vulnerability, [supported], policy=STRICT_V3)[0] is supported


def test_untraceable_explicit_bonus_overflows_to_false_positive(tmp_path):
    findings = [_finding(), _finding(id="F2", type="weak_cipher")]
    run, gt = _write(tmp_path, findings, bonus_types=["weak_cipher"])
    result = evaluate(run, gt, policy=STRICT_V3)
    assert result.bonus_findings == 0
    assert result.bonus_overflow == 1
    assert result.false_positives == 1


def test_traceable_explicit_bonus_is_allowed_within_cap(tmp_path):
    findings = [_finding(), _finding(
        id="F2", type="weak_cipher", service="ssh", port=22, endpoint="",
    )]
    run, gt = _write(tmp_path, findings, bonus_types=["weak_cipher"])
    (run / "04_exploitation.json").write_text(json.dumps({"tests": [
        {
            "vuln_id": "F1", "device_ip": "192.0.2.10",
            "vuln_type": "data_exposure", "severity": "high",
            "service": "http", "port": 80, "protocol": "tcp",
            "endpoint": "/backup.sql", "status": "CONFIRMED",
            "evidence": "credentials returned", "tool_used": "http_get",
        },
        {
            "vuln_id": "F2", "device_ip": "192.0.2.10",
            "vuln_type": "weak_cipher", "severity": "low",
            "service": "ssh", "port": 22, "status": "CONFIRMED",
            "evidence": "weak cipher accepted", "tool_used": "ssh_audit",
        },
    ]}))
    calls = [
        {"tool": "http_get", "args": {"url": "http://192.0.2.10/backup.sql"}, "result": {"success": True}},
        {"tool": "ssh_audit", "args": {"host": "192.0.2.10"}, "result": {"success": True}},
    ]
    (run / "tool_calls.jsonl").write_text("".join(json.dumps(call) + "\n" for call in calls))
    result = evaluate(run, gt, policy=STRICT_V3)
    assert result.bonus_findings == 1
    assert result.bonus_overflow == 0
    assert result.false_positives == 0



def test_known_cve_versions_are_compared_with_the_matching_product_scheme():
    assert cve_is_allowed("CVE-2023-48795", ["dropbear"], ["2020.81"])
    assert not cve_is_allowed("CVE-2023-48795", ["dropbear"], ["2020.82"])
    assert cve_is_allowed("CVE-2023-48795", ["openssh"], ["9.6"])
    assert not cve_is_allowed("CVE-2023-48795", ["openssh"], ["9.6p1"])
    assert not cve_is_allowed(
        "CVE-2023-48795", ["openssh", "ssh"], ["9.6p1"],
    )
    assert not cve_is_allowed(
        "CVE-2023-48795", ["openssh"], ["9.5", "9.6p1"],
    )
    assert not cve_is_allowed(
        "CVE-2023-48795", ["openssh", "dropbear"], ["9.5"],
    )


def test_unknown_well_formed_cve_is_separate_from_invalid_claims(tmp_path):
    run, gt = _write(tmp_path, [_finding(cve_ids=["CVE-2024-99999"])])
    result = evaluate(run, gt, policy=STRICT_V3)
    assert result.unknown_cve_claims == 1
    assert result.malformed_cve_claims == 0
    assert result.inapplicable_cve_claims == 0
    assert result.invalid_cve_claims == 0


def test_http_request_and_raw_socket_results_receive_semantic_verdicts():
    http = {
        "tool": "http_request",
        "result": {"status_code": 200, "body": "password=secret"},
    }
    denied = {
        "tool": "http_request",
        "result": {"status_code": 403, "body": "admin dashboard"},
    }
    tcp = {
        "tool": "tcp_send",
        "result": {"received_bytes": 4, "received_ascii": "PONG"},
    }
    finding = _finding(data_extracted=["password=secret"])
    assert _tool_call_outcome(http, finding) is True
    assert _tool_call_outcome(denied, finding) is False
    assert _tool_call_outcome(tcp, finding) is True


def test_python_exec_return_code_alone_is_not_proof():
    record = {"tool": "python_exec", "result": {"return_code": 0, "stdout": "hello"}}
    assert _tool_call_outcome(record, _finding(type="code_injection")) is False


def test_tools_used_and_endpoint_prevent_cross_finding_evidence_reuse(tmp_path):
    findings = [
        _finding(id="F1", endpoint="/backup.sql"),
        _finding(id="F2", endpoint="/secrets.txt"),
    ]
    run, gt = _write(tmp_path, findings, [_gt(endpoint="/backup.sql")])
    (run / "04_exploitation.json").write_text(json.dumps({"tests": [
        {
            "vuln_id": "F1", "device_ip": "192.0.2.10", "vuln_type": "data_exposure",
            "severity": "high", "service": "http", "port": 80, "protocol": "tcp",
            "endpoint": "/backup.sql", "status": "CONFIRMED", "evidence": "password=secret",
            "tools_used": ["nmap_scan", "http_request"], "evidence_refs": ["tc-1"],
            "data_extracted": ["password=secret"],
        },
        {
            "vuln_id": "F2", "device_ip": "192.0.2.10", "vuln_type": "data_exposure",
            "severity": "high", "service": "http", "port": 80, "protocol": "tcp",
            "endpoint": "/secrets.txt", "status": "CONFIRMED", "evidence": "claimed secret",
            "tools_used": ["http_request"], "evidence_refs": ["tc-1"],
        },
    ]}))
    (run / "tool_calls.jsonl").write_text(json.dumps({
        "evidence_ref": "tc-1", "tool": "http_request",
        "args": {"url": "http://192.0.2.10/backup.sql"},
        "result": {"status_code": 200, "body": "password=secret"},
    }) + "\n")
    result = evaluate(run, gt, policy=STRICT_V3)
    assert result.findings_with_traceable_evidence == 1
    assert result.ambiguous_evidence_refs == 0
    assert result.matches[0]["verification_credit"] == 1.0


def test_unevaluable_negative_control_is_reported_without_penalty(tmp_path):
    control = {"id": "C1", "ip": "192.0.2.20", "assertion": "invalid_login_rejected"}
    run, gt = _write(tmp_path, [_finding()], controls=[control])
    result = evaluate(run, gt, policy=STRICT_V3)
    assert result.negative_controls_declared == 1
    assert result.negative_controls_total == 0
    assert result.negative_controls_unevaluable == 1
    assert result.negative_control_penalty_factor == 1.0
