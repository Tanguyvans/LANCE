"""Adversarial Phase 3 triage regressions (offline synthetic targets only)."""
import json
from unittest.mock import MagicMock

import pytest

from src.agent.pipeline import Pipeline
from src.agent.registry import AGENTS
from src.agent.report_evidence import is_verified_report_finding


@pytest.fixture
def aggregate(tmp_path, monkeypatch):
    monkeypatch.setattr("src.agent.pipeline.OUTPUT_DIR", tmp_path)
    monkeypatch.setattr("src.agent.core.runtime.get_attack_surface", lambda: "[]")
    provider = MagicMock()
    provider.model = "offline-review-model"
    provider.provider = "test-provider"
    pipeline = Pipeline(provider=provider, execution_profile="full")
    path = pipeline.run_dir / "03_device_review.json"

    def run(findings):
        path.write_text(json.dumps({"vulnerabilities": findings}), encoding="utf-8")
        pipeline._aggregate_device_vulns(AGENTS["vuln_analysis"])
        return (
            json.loads((pipeline.run_dir / "03_vuln_analysis.json").read_text()),
            json.loads((pipeline.run_dir / "03_vuln_analysis_raw.json").read_text()),
        )

    return run


def finding(**kwargs):
    return {
        "device_id": "review-web", "device_ip": "192.0.2.10",
        "type": "data_exposure", "severity": "MEDIUM", "service": "http",
        "port": 80, "protocol": "tcp", "endpoint": "/config",
        "details": "A sensitive configuration file may be exposed at this path",
        "product": "", "version": "", **kwargs,
    }


def test_distinct_s1_patterns_are_not_suppressed(aggregate):
    inputs = [
        finding(type="directory_listing", endpoint="/backup/", details="Directory listing enabled on backup directory"),
        finding(endpoint="/backup/db.sql", details="Database backup may be publicly readable"),
        finding(type="missing_header", endpoint="/", severity="LOW", details="Missing X-Frame-Options"),
        finding(type="weak_cipher", service="ssh", port=22, endpoint="", device_id="review-a", details="SSH cipher CBC enabled"),
        finding(type="weak_cipher", service="ssh", port=22, endpoint="", device_id="review-b", device_ip="192.0.2.11", details="SSH cipher CBC enabled"),
    ]
    canonical, raw = aggregate(inputs)
    assert len(canonical["vulnerabilities"]) == len(inputs)
    assert all(r["accepted_for_canonical"] for r in raw["candidates"])


@pytest.mark.parametrize("change", [
    {"device_ip": "192.0.2.11", "device_id": "other"},
    {"port": 8080}, {"protocol": "udp"}, {"endpoint": "/Config"},
    {"endpoint": "/config?tenant=B"}, {"product": "different-product"},
    {"version": "2"}, {"endpoints": ["/config", "/admin"]},
])
def test_distinct_structural_identity_survives(aggregate, change):
    canonical, _ = aggregate([finding(), finding(**change)])
    assert len(canonical["vulnerabilities"]) == 2


@pytest.mark.parametrize("kind,service,port,details", [
    ("default_credentials", "http", 80, "Try the vendor default admin credentials on the login form"),
    ("code_injection", "http", 80, "The /api/exec endpoint may accept a shell command"),
    ("misconfiguration", "ssh", 22, "SSH may allow unrestricted TCP forwarding; verify AllowTcpForwarding"),
    ("data_exposure", "redis", 6379, "A sensitive key may be readable without authentication"),
])
def test_hypothesis_does_not_require_prior_confirmation(aggregate, kind, service, port, details):
    canonical, _ = aggregate([finding(type=kind, service=service, port=port, details=details)])
    assert len(canonical["vulnerabilities"]) == 1
    assert not is_verified_report_finding(canonical["vulnerabilities"][0])


def test_distinct_conditions_same_endpoint_survive(aggregate):
    canonical, _ = aggregate([
        finding(type="misconfiguration", service="ssh", port=22, endpoint="", details="TCP forwarding may allow unrestricted egress"),
        finding(type="misconfiguration", service="ssh", port=22, endpoint="", details="Private key permissions may be world-readable"),
    ])
    assert len(canonical["vulnerabilities"]) == 2


def test_exact_duplicates_keep_both_provenances(aggregate):
    canonical, raw = aggregate([
        finding(id="model-first", evidence_refs=["proof-one"]),
        finding(id="model-second", evidence_ref="proof-two"),
    ])
    assert len(canonical["vulnerabilities"]) == 1
    item = canonical["vulnerabilities"][0]
    refs = set(item.get("evidence_refs") or []) | {item.get("evidence_ref")}
    assert {"proof-one", "proof-two"} <= refs
    assert len(item["_provenance"]["candidate_ids"]) == 2
    assert len({r["canonical_finding_id"] for r in raw["candidates"]}) == 1
    assert {r["decision"] for r in raw["candidates"]} == {"selected", "deduplicated"}


def test_ids_survive_reaggregation_and_reordering(aggregate):
    a, b = finding(endpoint="/config"), finding(endpoint="/Config")
    first, _ = aggregate([a, b])
    old = {x["endpoint"]: x["id"] for x in first["vulnerabilities"]}
    second, _ = aggregate([b, finding(endpoint="/new"), a])
    new = {x["endpoint"]: x["id"] for x in second["vulnerabilities"]}
    assert all(new[k] == v for k, v in old.items())
    assert new["/new"] not in old.values()


def test_malformed_entry_does_not_break_healthy_candidates(aggregate):
    canonical, raw = aggregate([None, finding(), {"type": "data_exposure"}])
    assert len(canonical["vulnerabilities"]) == 1
    assert canonical["vulnerabilities"][0]["device_ip"] == "192.0.2.10"
    assert raw["candidate_count"] == 3
    assert all(r["decision"] != "pending" and r["decision_reason"] for r in raw["candidates"])


@pytest.mark.parametrize("extra", [
    {"type": "directory_listing", "endpoint": "/uploads/", "details": "Check whether uploaded files are exposed by a directory listing"},
    {"type": "weak_cipher", "service": "https", "port": 9443, "details": "TLS may allow deprecated cipher suites on this HTTPS service"},
    {"type": "weak_cipher", "service": "ftp", "port": 2121, "details": "FTP STARTTLS may allow deprecated cipher suites"},
    {"type": "insecure_protocol", "service": "http", "port": 80, "details": "The login form may submit credentials over cleartext HTTP"},
])
def test_a_conventional_path_or_port_is_not_a_proof_gate(aggregate, extra):
    canonical, _ = aggregate([finding(**extra)])
    assert len(canonical["vulnerabilities"]) == 1


@pytest.mark.parametrize("assessments,expected", [
    ({}, 1),
    ({"CVE-2025-10000": "incompatible", "CVE-2025-10001": "incompatible"}, 0),
    ({"CVE-2025-10000": "incompatible"}, 1),
])
def test_unknown_cve_compatibility_is_not_incompatibility(aggregate, monkeypatch, assessments, expected):
    monkeypatch.setattr(Pipeline, "_load_cve_search_evidence", lambda self: {
        ("review-product", cve): {"status": status, "reason": "Synthetic offline compatibility assessment"}
        for cve, status in assessments.items()
    })
    item = finding(
        type="known_cve", product="review-product", version="1.2.3",
        cve_ids=["CVE-2025-10000", "CVE-2025-10001"],
        cve_validation={"query": "review-product"},
    )
    canonical, raw = aggregate([item])
    assert len(canonical["vulnerabilities"]) == expected
    assert all(r["decision"] != "pending" and r["decision_reason"] for r in raw["candidates"])
    if expected:
        assert "CVE-2025-10001" in canonical["vulnerabilities"][0]["cve_ids"]


def test_cve_hypothesis_does_not_need_a_previous_search(aggregate):
    canonical, _ = aggregate([finding(
        type="known_cve", product="review-product", version="1.2.3",
        cve_ids=["CVE-2025-10000"],
    )])
    assert len(canonical["vulnerabilities"]) == 1


@pytest.mark.parametrize("missing_field", ["product", "version"])
def test_cve_hypothesis_with_unknown_fingerprint_remains_schedulable(aggregate, missing_field):
    item = finding(
        type="known_cve", product="review-product", version="1.2.3",
        cve_ids=["CVE-2025-10000"],
    )
    item[missing_field] = ""
    canonical, _ = aggregate([item])
    assert len(canonical["vulnerabilities"]) == 1
    assert canonical["vulnerabilities"][0]["cve_claim_status"] == "unverified"
    assert canonical["vulnerabilities"][0]["accepted_for_scoring"] is False


def test_partial_cve_validation_does_not_drop_unknown_ids(aggregate, monkeypatch):
    monkeypatch.setattr(Pipeline, "_load_cve_search_evidence", lambda self: {
        ("review-product", "CVE-2025-10000"): {"status": "compatible"}
    })
    canonical, _ = aggregate([finding(
        type="known_cve", product="review-product", version="1.2.3",
        cve_ids=["CVE-2025-10000", "CVE-2025-10001"],
        cve_validation={"query": "review-product"},
    )])
    item = canonical["vulnerabilities"][0]
    assert set(item["cve_ids"]) == {"CVE-2025-10000", "CVE-2025-10001"}
    assert item.get("cve_claim_status") not in {"validated", "validated_catalog"}


@pytest.mark.parametrize("changes", [
    [{"parameter": "Role"}, {"parameter": "role"}],
    [{"details": "Default account Admin may be accepted"}, {"details": "Default account admin may be accepted"}],
])
def test_condition_identity_does_not_casefold_protocol_values(aggregate, changes):
    canonical, _ = aggregate([
        finding(type="default_credentials", **change) for change in changes
    ])
    assert len(canonical["vulnerabilities"]) == 2


def test_severity_is_not_a_rejection_reason(aggregate):
    canonical, _ = aggregate([finding(
        type="missing_header", severity="INFO", details="X-Frame-Options may be absent",
    )])
    assert len(canonical["vulnerabilities"]) == 1
