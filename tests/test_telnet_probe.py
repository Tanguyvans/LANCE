"""Offline transport and proof checks for the structured Telnet probe."""

import json
import socket

import pytest

from src.agent.exploit_evidence import synthesize_exploit_result
from src.agent.tools import recon_tools
from src.benchmark.evaluator import _tool_call_outcome


FINDING = {
    "type": "insecure_protocol", "service": "telnet",
    "device_ip": "192.0.2.1", "port": 23,
}
ARGS = {"host": "192.0.2.1", "port": 23, "timeout": 3}


@pytest.mark.parametrize("stage,error,reply,connected,status", [
    ("connect", socket.timeout, b"", False, "ERROR"),
    ("recv", socket.timeout, b"", True, "ERROR"),
    ("connect", ConnectionRefusedError, b"", False, "ERROR"),
    ("sendall", ConnectionResetError, b"", True, "ERROR"),
    ("recv", ConnectionResetError, b"", True, "ERROR"),
    ("", None, b"", True, "FAILED"),
    ("", None, b"uid=1000(gateway)\n", True, "EXPLOITED"),
    ("", None, b"Telnet login: ", True, "EXPLOITED"),
])
def test_probe_transport_and_verdict_agree(
    monkeypatch, stage, error, reply, connected, status,
):
    class FakeSocket:
        closed = False
        sent = b""

        def fail(self, operation):
            if stage == operation:
                raise error("synthetic transport failure")

        def settimeout(self, value):
            assert value == 3

        def connect(self, address):
            assert address == ("192.0.2.1", 23)
            self.fail("connect")

        def sendall(self, payload):
            self.sent = payload
            self.fail("sendall")

        def recv(self, size):
            assert size <= 4096
            self.fail("recv")
            return reply

        def close(self):
            self.closed = True

    transport = FakeSocket()
    monkeypatch.setattr(recon_tools.socket, "socket", lambda *_: transport)
    result = json.loads(recon_tools.telnet_connect(**ARGS))
    assert result["connected"] is connected
    assert result["host"] == ARGS["host"]
    assert result["port"] == ARGS["port"]
    assert result["received_bytes"] == len(reply)
    assert transport.closed
    if connected:
        assert transport.sent == b"id\n"
    if error is socket.timeout:
        assert result["timed_out"] is True
    record = {"tool": "telnet_connect", "args": ARGS, "result": result}
    assert synthesize_exploit_result(FINDING, [record])["status"] == status
    assert _tool_call_outcome(record, FINDING) is (status == "EXPLOITED")


@pytest.mark.parametrize("result", [
    {"connected": True, "received_bytes": 0, "success": True},
    {"connected": True, "received_bytes": 0, "status": "success"},
    {"connected": True, "received_bytes": 0, "ok": True},
    {"connected": True, "received_bytes": 8,
     "received_ascii": "uid=1000", "timed_out": True},
    {"connected": True, "received_bytes": 8,
     "received_ascii": "uid=1000", "error": "synthetic read error"},
    {"return_code": 124, "stdout": "Connected; waiting for data"},
    {"return_code": 0, "stdout": "", "stderr": "Local diagnostic only"},
])
def test_metadata_and_local_diagnostics_are_not_remote_proof(result):
    record = {"tool": "telnet_connect", "args": ARGS, "result": result}
    assert synthesize_exploit_result(FINDING, [record])["status"] != "EXPLOITED"
    assert _tool_call_outcome(record, FINDING) is False


def test_registered_tool_exposes_the_structured_probe():
    tool = next(t for t in recon_tools.RECON_TOOLS if t["name"] == "telnet_connect")
    assert tool["function"] is recon_tools.telnet_connect
    properties = tool["input_schema"]["properties"]
    assert set(properties) == {"host", "port", "timeout"}
    assert set(tool["input_schema"]["required"]) == {"host", "port"}


@pytest.mark.parametrize("host,response,expected_tp", [
    ("192.0.2.1", {"connected": True, "received_bytes": 8,
                   "received_ascii": "uid=1000"}, 1),
    ("192.0.2.1", {"connected": True, "received_bytes": 0,
                   "timed_out": True}, 0),
    ("192.0.2.1", {"connected": True, "received_bytes": 0}, 0),
    ("192.0.2.2", {"connected": True, "received_bytes": 8,
                   "received_ascii": "uid=1000"}, 0),
])
def test_final_funnel_requires_response_and_correct_destination(
    tmp_path, host, response, expected_tp,
):
    from tests.test_evaluation_audit import _confirmed, _evaluate, _finding, _truth

    finding = _finding(**FINDING, endpoint="")
    truth = _truth(category="insecure_protocol", accepted_types=["insecure_protocol"],
                   services=["telnet"], ports=[23], endpoints=[])
    record = {
        "vuln_id": finding["id"], "evidence_ref": "proof-V1",
        "tool": "telnet_connect", "args": {**ARGS, "host": host}, "result": response,
    }
    result = _evaluate(tmp_path, [finding], [truth],
                       tests=[_confirmed(finding, tool="telnet_connect")], records=[record])
    final = result.funnel["stages"]["confirmed"]
    assert final["true_positives"] == expected_tp
    assert final["invalid_evidence"] == 1 - expected_tp
