"""Regression tests for the evidence-aware evaluation contracts."""
from __future__ import annotations

import json

import pytest
import yaml

from src.benchmark.evaluator import _record_implied_endpoints, _strict_v3_match, evaluate
from src.agent.exploit_evidence import (
    _positive_cve_result,
    extract_endpoint_paths,
    synthesize_exploit_result,
)
from src.benchmark.metric_contract import EVIDENCE_CONTRACT_VERSION, METRIC_CONTRACT_VERSION
from src.benchmark.strict_v3 import derive_matching_contract


def _finding(**changes):
    return {
        "id": "V1", "device_id": "web", "device_ip": "192.0.2.1",
        "type": "data_exposure", "service": "http", "port": 80,
        "protocol": "tcp", "endpoint": "/backup", "severity": "high",
        "product": "", "version": "", "details": "Sensitive file exposure",
        **changes,
    }


def _truth(**changes):
    return {
        "id": "GT1", "ip": "192.0.2.1", "title": "Sensitive file exposure",
        "category": "data_exposure", "accepted_types": ["data_exposure"],
        "services": ["http"], "ports": [80], "protocols": ["tcp"],
        "endpoints": ["/backup"], "severity": "high", **changes,
    }


def _evaluate(tmp_path, findings, ground_truth, tests=None, records=None):
    (tmp_path / "run_meta.json").write_text(json.dumps({
        "metric_contract_version": METRIC_CONTRACT_VERSION,
        "evidence_contract_version": EVIDENCE_CONTRACT_VERSION,
    }))
    (tmp_path / "03_vuln_analysis_raw.json").write_text(json.dumps({
        "candidates": [{"candidate_finding": f, "decision": "selected"} for f in findings],
    }))
    (tmp_path / "03_vuln_analysis.json").write_text(json.dumps({"vulnerabilities": findings}))
    (tmp_path / "04_exploitation.json").write_text(json.dumps({"tests": tests or []}))
    (tmp_path / "tool_calls.jsonl").write_text(
        "".join(json.dumps(record) + "\n" for record in (records or []))
    )
    gt = tmp_path / "truth.yaml"
    gt.write_text(yaml.safe_dump({"scenario_id": "audit-demo", "vulnerabilities": ground_truth}))
    return evaluate(tmp_path, gt, policy="strict-v3")


def _confirmed(finding, tool="http_get"):
    return {
        "vuln_id": finding["id"], "status": "CONFIRMED", "evidence_level": 2,
        "tool_used": tool, "evidence_refs": [f"proof-{finding['id']}"],
        "evidence": "token=synthetic-fixture",
    }


def _proof(finding, endpoint=None, body="token=synthetic-fixture"):
    return {
        "vuln_id": finding["id"], "evidence_ref": f"proof-{finding['id']}",
        "tool": "http_get", "args": {
            "url": f"http://192.0.2.1{endpoint or finding['endpoint']}",
        }, "result": {"return_code": 0, "status_code": 200, "body": body},
    }


def test_conditions_are_canonical_predictions_and_coverage_uses_their_ids(tmp_path):
    first = _finding(details="Database credential exposed")
    second = _finding(id="V2", details="Private signing key exposed")
    result = _evaluate(tmp_path, [first, second], [_truth()], tests=[{"vuln_id": "V2", "status": "ERROR"}])
    assert result.funnel["stages"]["filtered"]["predictions"] == 2
    assert result.funnel["diagnostics"]["verification_attempt_rate"] == 0.5
    assert result.funnel["diagnostics"]["orphan_tests"] == 0


def test_exact_duplicate_ids_are_not_orphaned_in_queue_coverage(tmp_path):
    first = _finding(details="Same precise hypothesis")
    second = {**first, "id": "V2"}
    result = _evaluate(tmp_path, [first, second], [_truth()], tests=[{"vuln_id": "V2", "status": "ERROR"}])
    diagnostics = result.funnel["diagnostics"]
    assert result.funnel["stages"]["filtered"]["predictions"] == 1
    assert (diagnostics["verification_attempt_rate"], diagnostics["orphan_tests"]) == (0.5, 0)


@pytest.mark.parametrize("expected,observed", [("/Config", "/config"), ("/export?tenant=owner", "/export?tenant=other")])
def test_route_case_and_query_are_structural(tmp_path, expected, observed):
    finding = _finding(endpoint=observed)
    result = _evaluate(tmp_path, [finding], [_truth(endpoints=[expected])], tests=[_confirmed(finding)], records=[_proof(finding)])
    assert result.funnel["stages"]["confirmed"]["true_positives"] == 0


@pytest.mark.parametrize("expected,observed", [("/Config", "/config"), ("/export?tenant=owner", "/export?tenant=other")])
def test_proof_must_target_claimed_route(tmp_path, expected, observed):
    finding = _finding(endpoint=expected)
    result = _evaluate(tmp_path, [finding], [_truth(endpoints=[expected])], tests=[_confirmed(finding)], records=[_proof(finding, observed)])
    assert result.funnel["stages"]["confirmed"]["invalid_evidence"] == 1


def test_explicit_root_route_is_not_a_wildcard(tmp_path):
    finding = _finding(endpoint="/")
    result = _evaluate(
        tmp_path, [finding], [_truth(endpoints=["/"])],
        tests=[_confirmed(finding)], records=[_proof(finding, "/backup")],
    )
    assert result.funnel["stages"]["confirmed"]["invalid_evidence"] == 1


def test_urls_in_payload_do_not_become_call_provenance(tmp_path):
    finding = _finding(endpoint="/admin")
    record = _proof(finding, "/public")
    record["args"]["body"] = "see https://192.0.2.1/admin"
    result = _evaluate(tmp_path, [finding], [_truth(endpoints=["/admin"])], tests=[_confirmed(finding)], records=[record])
    assert result.funnel["stages"]["confirmed"]["invalid_evidence"] == 1


def test_cve_matching_applies_service_port_protocol_contradictions():
    gt = _truth(category="cve", accepted_types=["known_cve"], cve="CVE-2023-48795", services=["ssh"], ports=[22], protocols=["tcp"], products=["dropbear"], versions=["2020.81"], endpoints=[])
    finding = _finding(type="known_cve", service="ssh", port=22, endpoint="", product="dropbear", version="2020.81", cve_ids=["CVE-2023-48795"])
    for change in ({"service": "http", "port": 8080}, {"port": 2222}, {"protocol": "udp"}):
        candidate = {**finding, **change}
        assert _strict_v3_match(gt, candidate)[1] == 0


def test_explicit_port_is_not_rewritten_by_title():
    gt = _truth(title="SSH weak cipher", accepted_types=["weak_cipher"], services=["ssh"], ports=[2222], endpoints=[])
    assert derive_matching_contract(gt)["ports"] == [2222]


@pytest.mark.parametrize("field,value", [
    ("services", ["mqtt"]), ("ports", [2222]), ("protocols", ["udp"]),
    ("services", []), ("ports", []), ("protocols", []),
])
def test_explicit_contract_fields_are_not_reinterpreted(field, value):
    gt = _truth(title="SSH finding")
    gt[field] = value
    assert derive_matching_contract(gt)[field] == value


@pytest.mark.parametrize("field", ["products", "versions"])
def test_explicit_empty_fingerprint_is_not_inferred_from_title(field):
    gt = {"title": "Dropbear 2020.81 vulnerability", "category": "cve", field: []}
    assert derive_matching_contract(gt)[field] == []


def test_legacy_contract_still_derives_missing_fields():
    assert derive_matching_contract({"title": "SSH weak cipher", "category": "weak_crypto"})["ports"] == [22]


def test_mqtt_topic_without_slash_is_not_an_http_path():
    gt = _truth(category="no_authentication", accepted_types=["no_auth"], services=["mqtt"], ports=[1883], endpoints=["/smartcity/admin"])
    candidate = _finding(type="no_auth", service="mqtt", port=1883, endpoint="smartcity/admin")
    assert _strict_v3_match(gt, candidate)[1] == 0


def test_endpoint_extraction_keeps_query_as_part_of_route():
    assert extract_endpoint_paths("http://192.0.2.1/export?tenant=Owner") == ["/export?tenant=Owner"]


def test_mixed_cve_declaration_requires_evidence_for_every_claimed_cve():
    finding = _finding(type="known_cve", service="ssh", port=22, endpoint="", product="dropbear", version="2020.81", cve_ids=["CVE-2023-48795", "CVE-2021-36369"])
    result = synthesize_exploit_result(finding, [{
        "tool": "ssh_audit", "args": {"host": "192.0.2.1", "port": 22},
        "result": {"return_code": 0, "stdout": "CVE-2021-36369: VULNERABLE"},
    }])
    assert result["status"] != "EXPLOITED"


@pytest.mark.parametrize("output", [
    "Reference: Terrapin (CVE-2023-48795)",
    "CVE-2023-48795: not yet confirmed",
    "CVE-2023-48795: affected versions include 2020.81",
    "CVE-2023-48795: database description says exploitable on other versions",
    "CVE-2023-48795: this reference describes vulnerable software",
    "CVE-2023-48795: vulnerable=false",
    "CVE-2023-48795: vulnerable: unknown",
    "CVE-2023-48795: VULNERABLE\n" + ("diagnostic\n" * 20) + "CVE-2023-48795: NOT VULNERABLE",
])
def test_cve_uncertainty_or_distant_conflict_is_not_proof(output):
    assert not _positive_cve_result(output, ["CVE-2023-48795"])


def test_explicit_cve_version_conflict_is_not_saved_by_prose():
    finding = _finding(type="known_cve", service="ssh", port=22, endpoint="", product="dropbear", version="2099.1", cve_ids=["CVE-2023-48795"], details="Expected vulnerable version was Dropbear 2020.81")
    gt = _truth(category="cve", accepted_types=["known_cve"], cve="CVE-2023-48795", services=["ssh"], ports=[22], products=["dropbear"], versions=["2020.81"], endpoints=[])
    assert _strict_v3_match(gt, finding)[1] == 0


@pytest.mark.parametrize("tool,output,return_code", [
    ("ssh_audit", "[warn] vulnerable to Terrapin (CVE-2023-48795)", 3),
    ("nmap_scan", "22/tcp open ssh\n| State: VULNERABLE\n| IDs: CVE:CVE-2023-48795", 0),
])
def test_realistic_cve_positive_output_is_preserved(tool, output, return_code):
    finding = _finding(
        type="known_cve", service="ssh", port=22, endpoint="",
        product="dropbear", version="2020.81", cve_ids=["CVE-2023-48795"],
    )
    result = synthesize_exploit_result(finding, [{
        "tool": tool, "args": {"host": "192.0.2.1", "port": 22},
        "result": {"return_code": return_code, "stdout": output},
    }])
    assert result["status"] == "EXPLOITED"


@pytest.mark.parametrize("verdict", ["not confirmed", "not exploitable", "vulnerable: false"])
def test_negative_cve_verdict_is_never_proof(verdict):
    assert not _positive_cve_result("CVE-2023-48795: " + verdict, ["CVE-2023-48795"])


@pytest.mark.parametrize("payload_key", ["body", "headers", "payload"])
def test_nested_payload_url_is_not_a_destination(payload_key):
    record = {"tool": "http_request", "args": {
        "url": "http://192.0.2.1/public",
        payload_key: {"url": "http://192.0.2.1/admin"},
    }}
    assert _record_implied_endpoints(record) == {"/public"}


@pytest.mark.parametrize("explicit_services", [[], ["http"]])
def test_websocket_title_cannot_override_explicit_services(explicit_services):
    contract = derive_matching_contract({
        "title": "MQTT websocket", "category": "no_authentication",
        "services": explicit_services, "ports": [9001],
    })
    assert contract["services"] == explicit_services


def test_legacy_url_inference_preserves_query():
    contract = derive_matching_contract({
        "title": "Sensitive file exposure", "category": "data_exposure",
        "verification": "curl http://192.0.2.1/export?tenant=Owner",
    })
    assert contract["endpoints"] == ["/export?tenant=Owner"]


@pytest.mark.parametrize("tool,stdout", [
    ("ssh_audit", "(cve) CVE-2023-48795: not vulnerable (patched)"),
    ("nmap_scan", "22/tcp open ssh\nCVE-2018-15473: VULNERABLE"),
    ("nmap_scan", "22/tcp open ssh\nCVE-2023-48795: NOT VULNERABLE"),
])
def test_cve_proof_requires_positive_claimed_result(tmp_path, tool, stdout):
    finding = _finding(type="known_cve", service="ssh", port=22, endpoint="", product="dropbear", version="2020.81", cve_ids=["CVE-2023-48795"])
    gt = _truth(category="cve", accepted_types=["known_cve"], cve="CVE-2023-48795", services=["ssh"], ports=[22], products=["dropbear"], versions=["2020.81"], endpoints=[])
    args = {"host": "192.0.2.1", "port": 22} if tool == "ssh_audit" else {"target": "192.0.2.1", "ports": "22"}
    record = {"vuln_id": "V1", "evidence_ref": "proof-V1", "tool": tool, "args": args, "result": {"return_code": 0, "stdout": stdout}}
    result = _evaluate(tmp_path, [finding], [gt], tests=[_confirmed(finding, tool)], records=[record])
    assert result.funnel["stages"]["confirmed"]["true_positives"] == 0
    assert result.funnel["stages"]["confirmed"]["invalid_evidence"] == 1
