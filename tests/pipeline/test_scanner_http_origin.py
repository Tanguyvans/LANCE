"""HTTP exposure keeps the observed origin through aggregation and phase 4."""
import json

import pytest

from src.agent.scanner import extract_findings
from src.agent.phases.analysis.aggregation import aggregate
from src.agent.phases.analysis.aggregation_context import AggregationContext
from src.agent.phases.verification.contract import _phase4_http_target


HOST = "192.0.2.10"


def entry(url):
    return {
        "tool": "curl_headers", "kwargs": {"url": url},
        "result": json.dumps({"stdout": 'HTTP/1.1 200 OK\r\n\r\n{"password":"offline-secret"}', "return_code": 0}),
    }


@pytest.mark.parametrize("origin,service,port", [
    (f"https://{HOST}:8443", "https", 8443),
    (f"http://{HOST}:8080", "http", 8080),
    (f"https://{HOST}", "https", 443), (f"http://{HOST}", "http", 80),
])
def test_http_exposure_retains_origin_in_canonical_finding_and_verification(tmp_path, origin, service, port):
    extracted = extract_findings({"web": [entry(origin + "/config")]}, {"id": "web", "ip": HOST})
    exposures = [finding for finding in extracted if finding["type"] == "data_exposure"]
    item, = exposures
    assert (item["service"], item["port"]) == (service, port)
    (tmp_path / "03_device_web.json").write_text(json.dumps({"vulnerabilities": exposures}))
    result = aggregate(AggregationContext(run_dir=tmp_path))
    canonical, = result.canonical["vulnerabilities"]
    assert _phase4_http_target(canonical) == (origin, port)
    assert canonical["endpoint"] == "/config"


def test_distinct_http_origins_keep_separate_evidence():
    entries = [entry(f"https://{HOST}:8443/config"), entry(f"http://{HOST}:8443/backup")]
    findings = extract_findings({"web": entries}, {"id": "web", "ip": HOST})
    exposures = [finding for finding in findings if finding["type"] == "data_exposure"]
    assert {(item["service"], item["port"], item["endpoint"]) for item in exposures} == {
        ("https", 8443, "/config"), ("http", 8443, "/backup"),
    }
    assert all(item["details"].count("Sensitive data exposed") == 1 for item in exposures)
    assert all(("/backup" in item["details"]) != ("/config" in item["details"]) for item in exposures)


@pytest.mark.parametrize("url", ["https://192.0.2.20/config", f"https://{HOST}:bad/config", f"https://{HOST}:0/config", "/config"])
def test_unverifiable_http_origin_does_not_claim_exposure_on_this_device(url):
    findings = extract_findings({"web": [entry(url)]}, {"id": "web", "ip": HOST})
    assert not any(finding["type"] == "data_exposure" for finding in findings)
