"""A broker denial is negative access evidence, never anonymous success. No broker is contacted."""
import json

import pytest

from src.agent.tools.outcomes import tool_execution_failed


DENIED = {
    "stdout": "",
    "stderr": "Connection error: Connection Refused: not authorised.\n",
    "return_code": 5,
    "interpretation": "connection_refused_auth_required",
}


@pytest.mark.parametrize("encoding", [dict, json.dumps])
def test_recognized_broker_denial_is_a_completed_probe(encoding):
    assert tool_execution_failed("mqtt_listen", encoding(DENIED)) is False


@pytest.mark.parametrize("overrides", [
    {"return_code": 1},
    {"return_code": "5"},
    {"return_code": 5.0},
    {"return_code": True},
    {"interpretation": None},
    {"interpretation": "generic_error_broker_unreachable"},
    {"stderr": "Error: Connection refused"},
    {"stderr": "Timed out"},
    {"stderr": ""},
    {"stdout": "sensors/temp 22"},
    {"timed_out": True},
    {"cancelled": True},
    {"error": "Connection failed"},
    {"exception_type": "TimeoutError"},
    {"ok": False},
])
def test_broker_marker_cannot_hide_other_failures(overrides):
    assert tool_execution_failed("mqtt_listen", {**DENIED, **overrides}) is True


@pytest.mark.parametrize("tool", ["nmap_scan", "ssh_audit", "curl_headers", "mqtt_ws_listen"])
def test_mqtt_denial_is_not_a_generic_exit_code_exception(tool):
    assert tool_execution_failed(tool, DENIED) is True


@pytest.mark.parametrize("probe,expected_failure", [
    (DENIED, False),
    ({"stdout": "", "stderr": "Error: Connection refused", "return_code": 1}, True),
])
def test_scanner_preserves_negative_access_and_detects_transport_failure(tmp_path, monkeypatch, probe, expected_failure):
    from src.agent.scanner import run_scanner

    monkeypatch.setattr("src.agent.tools.tool_loader.filter_unavailable_tools", lambda tools: (tools, {}))
    calls = []

    def mqtt(**kwargs):
        calls.append(kwargs)
        return json.dumps(probe)

    tools = [
        {"name": "mqtt_listen", "function": mqtt},
        {"name": "nmap_scan", "function": lambda **kwargs: json.dumps({
            "stdout": "9001/tcp closed tor-orport", "return_code": 0,
        })},
        {"name": "http_request", "function": lambda **kwargs: pytest.fail("Closed optional listener must not be requested")},
    ]
    result = run_scanner(tmp_path, [{
        "id": "broker", "ip": "192.0.2.11",
        "services": [{"name": "mqtt", "port": 1883}],
    }], tools=tools, max_workers=1)["broker"]
    assert bool(result.get("error")) is expected_failure
    assert len(calls) == 3
    assert result["findings"] == []
    archived = json.loads((tmp_path / "03_scans/broker.json").read_text())
    for entry in archived["mqtt"]:
        if entry["tool"] == "mqtt_listen":
            assert json.loads(entry["result"]) == probe
    fallback = json.loads((tmp_path / "03_device_broker.json").read_text())
    assert fallback["vulnerabilities"] == []
