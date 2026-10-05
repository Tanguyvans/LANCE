"""Fresh DNS scans use the observed endpoint and transport, without inventing findings."""
import json

import pytest

from src.agent.scanner import extract_findings, scan_device
from src.benchmark.tool_registry import tools_for_services


@pytest.mark.parametrize("service", ["domain", "dns"])
@pytest.mark.parametrize("protocol", ["tcp", "udp"])
@pytest.mark.parametrize("port", [53, 5353])
def test_dns_endpoint_is_actually_probed(service, protocol, port):
    calls = []

    def nmap(**kwargs):
        calls.append(kwargs)
        return json.dumps({"stdout": f"{port}/{protocol} open domain", "return_code": 0})

    device = {"id": "resolver", "ip": "192.0.2.10", "services": [
        {"name": service, "port": port, "protocol": protocol},
    ]}
    errors = []
    results = scan_device(device, {"nmap_scan": nmap}, diagnostics=errors)
    assert len(calls) == 1
    assert calls[0]["target"] == "192.0.2.10"
    assert calls[0]["ports"] == str(port)
    assert calls[0]["scripts"] == "dns-nsid"
    assert calls[0].get("udp_scan", False) is (protocol == "udp")
    assert not errors
    assert extract_findings(results, device) == []
    assert "nmap_scan" in tools_for_services([service], "recon")


def test_missing_dns_tool_keeps_incomplete_coverage_visible():
    errors = []
    scan_device({"id": "resolver", "ip": "192.0.2.10", "services": [
        {"name": "domain", "port": 53, "protocol": "tcp"},
    ]}, {}, diagnostics=errors)
    assert errors and "required tool nmap_scan unavailable" in errors[0]


def test_dns_transport_failure_still_marks_scanner_partial(tmp_path, monkeypatch):
    from src.agent.scanner import run_scanner

    monkeypatch.setattr("src.agent.tools.tool_loader.filter_unavailable_tools", lambda tools: (tools, {}))
    result = run_scanner(tmp_path, [{"id": "resolver", "ip": "192.0.2.10", "services": [
        {"name": "dns", "port": 53, "protocol": "tcp"},
    ]}], tools=[{"name": "nmap_scan", "function": lambda **kwargs: json.dumps({
        "stdout": "", "stderr": "scan failed", "return_code": 1,
    })}], max_workers=1)["resolver"]
    assert "returned an error" in result["error"]
    assert result["findings"] == []


def test_unrecognized_dns_transport_remains_incomplete():
    errors = []
    scan_device({"id": "resolver", "ip": "192.0.2.10", "services": [
        {"name": "dns", "port": 53, "protocol": "sctp"},
    ]}, {"nmap_scan": lambda **kwargs: pytest.fail("Do not replace an unknown transport")}, diagnostics=errors)
    assert errors == ["resolver: unsupported DNS transport sctp"]


@pytest.mark.parametrize("descriptor", [{}, {"protocol": None}, {"protocol": ""}])
def test_missing_dns_transport_is_not_guessed(descriptor):
    errors = []
    scan_device({"id": "resolver", "ip": "192.0.2.10", "services": [
        {"name": "dns", "port": 53, **descriptor},
    ]}, {"nmap_scan": lambda **kwargs: pytest.fail("No transport substitution")}, diagnostics=errors)
    assert errors == ["resolver: unsupported DNS transport unspecified"]
