"""Malformed model fields cannot discard healthy sibling findings on resume."""
import json

import pytest

from src.agent.phases.analysis.aggregation import aggregate
from src.agent.phases.analysis.aggregation_context import AggregationContext
from src.agent.validators import validate_json_device_vulns


def finding(**changes):
    return {
        "device_id": "web", "device_ip": "192.0.2.10", "type": "data_exposure",
        "severity": "MEDIUM", "service": "http", "port": 80,
        "protocol": "tcp", "endpoint": "/config", "details": "Configuration may expose a secret",
        **changes,
    }


@pytest.mark.parametrize("invalid,field", [
    ({"type": "known_cve", "cve_ids": None}, "cve_ids"),
    ({"severity": ["HIGH"]}, "severity"),
    ({"type": {}}, "type"), ({"service": []}, "service"),
    ({"cve_ids": [{"id": "CVE-2025-10000"}]}, "cve_ids"),
    ({"cve_validation": []}, "cve_validation"),
    ({"port": True}, "port"), ({"port": {"number": 80}}, "port"),
    ({"endpoints": [{"path": "/config"}]}, "endpoints"),
])
@pytest.mark.parametrize("compact", [False, True])
def test_invalid_fields_are_refused_and_isolated_with_raw_values_preserved(tmp_path, invalid, field, compact):
    healthy = finding()
    malformed = finding(endpoint="/other", **invalid)
    path = tmp_path / "03_device_web.json"
    path.write_text(json.dumps({"vulnerabilities": [healthy, malformed]}))
    before = path.read_bytes()
    valid, reason = validate_json_device_vulns(path.name, output_dir=tmp_path)
    assert valid is False and field in reason
    # Previously promoted/legacy files still need safe individual admission.
    result = aggregate(AggregationContext(run_dir=tmp_path, compact_local=compact))
    assert len(result.canonical["vulnerabilities"]) == 1
    assert result.canonical["vulnerabilities"][0]["endpoint"] == "/config"
    rejected = result.raw["candidates"][1]
    assert rejected["raw_finding"] == malformed
    assert rejected["decision"] == "rejected_malformed"
    assert field in rejected["decision_reason"]
    assert path.read_bytes() == before


def test_valid_nullable_scalars_and_numeric_ports_still_normalize(tmp_path):
    path = tmp_path / "03_device_web.json"
    path.write_text(json.dumps({"vulnerabilities": [finding(
        port="80", protocol=None, product=None, version=None, cve_ids=[],
    )]}))
    assert validate_json_device_vulns(path.name, output_dir=tmp_path) == (True, "OK")
    result = aggregate(AggregationContext(run_dir=tmp_path))
    item, = result.canonical["vulnerabilities"]
    assert item["port"] == 80 and item["protocol"] == "tcp"
    assert item["product"] == item["version"] == ""
