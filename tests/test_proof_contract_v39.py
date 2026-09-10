"""Strict-v3.9/evidence-v7 proof boundary regressions (offline fixtures)."""
import json

from src.agent.exploit_evidence import _text_has_sensitive_data, synthesize_exploit_result
from src.agent.phases.verification.contract import _phase4_requirement_matches, _phase4_verification_plan
from src.agent.tools import recon_tools
from src.benchmark.evaluator import _tool_call_outcome


def test_sql_known_tables_require_concrete_sensitive_column_value():
    assert _text_has_sensitive_data("INSERT INTO users (username, password) VALUES ('alice', 's3cret')")
    assert _text_has_sensitive_data("INSERT INTO api_keys (owner, api_key) VALUES ('alice', 'k_live_123')")
    assert not _text_has_sensitive_data("INSERT INTO users VALUES ('alice', NULL)")
    assert not _text_has_sensitive_data("INSERT INTO users (username, password) VALUES ('alice', '[redacted]')")
    assert not _text_has_sensitive_data("-- INSERT INTO users VALUES ('alice', 'secret')")


def test_http_secondary_endpoint_cannot_confirm_primary():
    vuln = {"id": "V1", "type": "data_exposure", "device_ip": "192.0.2.1", "port": 80, "endpoint": "/dump.sql"}
    record = {"tool": "http_get", "args": {"url": "http://192.0.2.1/config/app.config"},
              "result": {"status_code": 200, "body": '{"password":"s3cret"}'}}
    result = synthesize_exploit_result(vuln, [record])
    assert result["status"] == "FAILED"
    assert "http_get" in result["evidence"]


def test_telnet_plan_is_structured_and_bytes_are_required():
    vuln = {"type": "insecure_protocol", "service": "telnet", "device_ip": "192.0.2.1", "port": 23}
    requirement = _phase4_verification_plan(vuln)
    assert requirement["args_hint"] == {"host": "192.0.2.1", "port": 23, "timeout": 3}
    assert _phase4_requirement_matches(requirement, "telnet_connect", requirement["args_hint"])
    assert not _phase4_requirement_matches(requirement, "telnet_connect", {"command_string": "echo quit | nc 192.0.2.1 23"})


def test_telnet_connected_without_response_is_not_exploited():
    result = synthesize_exploit_result(
        {"type": "insecure_protocol", "service": "telnet", "port": 23},
        [{"tool": "telnet_connect", "args": {"host": "192.0.2.1", "port": 23, "timeout": 3},
          "result": {"connected": True, "received_bytes": 0, "timed_out": True}}],
    )
    assert result["status"] == "ERROR"


def test_telnet_handler_uses_fixed_probe_and_structured_result(monkeypatch):
    class FakeSocket:
        def __init__(self, *_args): self.sent = b""
        def settimeout(self, value): self.timeout = value
        def connect(self, address): self.address = address
        def sendall(self, payload): self.sent += payload
        def recv(self, _size): return b"uid=1000\n"
        def close(self): pass
    monkeypatch.setattr(recon_tools.socket, "socket", lambda *_args: FakeSocket())
    result = json.loads(recon_tools.telnet_connect("192.0.2.1", 23, 3))
    assert result["connected"] is True
    assert result["received_bytes"] > 0
    assert result["received_ascii"] == "uid=1000."


def test_sql_parser_boundaries_and_multiline_rows():
    cases = [
        ("SELECT 1; /* INSERT INTO users (password) VALUES ('fiction'); */", False),
        ("SELECT 'INSERT INTO users (password) VALUES (''fiction'')';", False),
        ("INSERT INTO users (password) VALUES (NULLIF('x','x'));", False),
        ("INSERT INTO users VALUES (1,'name',NULL,'mail');", False),
        ("INSERT INTO api_keys VALUES ('scope-only',7,'opaque-key-123456');", True),
        ("INSERT INTO api_keys VALUES (7,NULL),(8,'opaque-key-123456');", True),
        ("INSERT INTO users (password) VALUES ('\n/*literal*/\n');", True),
        ("INSERT INTO users (password) VALUES (SHA2('fixture',256));", False),
        ("INSERT INTO api_keys VALUES (7,NULL) /* 'opaque-key-123456' */;", False),
        ("INSERT INTO users (`password`) VALUES (NULL);", False),
    ]
    for text, expected in cases:
        assert _text_has_sensitive_data(text) is expected


def test_sql_parser_does_not_cross_statement_or_comment_boundaries():
    assert not _text_has_sensitive_data(
        "INSERT INTO api_keys VALUES (1,NULL); INSERT INTO products VALUES (2,'fixture-token-438');"
    )
    assert not _text_has_sensitive_data(
        "INSERT INTO api_keys VALUES (1,NULL) /* ('fixture-token-438') */;"
    )
    assert not _text_has_sensitive_data(
        "INSERT INTO users (password) VALUES (SHA2('fixture',256));"
    )
    assert not _text_has_sensitive_data(
        "INSERT INTO users (password) VALUES (/* 'fixture-token-438' */ NULL);"
    )
    assert not _text_has_sensitive_data("INSERT INTO users (password) VALUES ('   ');")
    assert not _text_has_sensitive_data("INSERT INTO users (password) VALUES (' [redacted] ');")
    assert not _text_has_sensitive_data("INSERT INTO users (password) VALUES (' *** ');")


def test_http_primary_identity_rejects_invalid_and_secondary_urls():
    vuln = {"type": "data_exposure", "device_ip": "192.0.2.1", "port": 8080,
            "endpoint": "http://192.0.2.1:8080/export?tenant=A"}
    good = {"url": "http://192.0.2.1:8080/export?tenant=A"}
    for url in ("http://192.0.2.1:8080/export?tenant=B", "http://192.0.2.2:8080/export?tenant=A", "ftp://192.0.2.1:8080/export?tenant=A", "http://192.0.2.1:bad/export?tenant=A"):
        assert synthesize_exploit_result(vuln, [{"tool": "http_get", "args": {"url": url}, "result": {"status_code": 200, "body": '{"password":"opaque-secret-123"}'}}])["status"] != "EXPLOITED"
    assert synthesize_exploit_result(vuln, [{"tool": "http_get", "args": good, "result": {"status_code": 200, "body": '{"password":"opaque-secret-123"}'}}])["status"] == "EXPLOITED"


def test_save_only_is_absence_but_inconclusive_output_is_failed():
    assert synthesize_exploit_result({"type": "data_exposure"}, [{"tool": "save_deliverable", "args": {}, "result": {"ok": True}}])["status"] == "ERROR"
    result = synthesize_exploit_result({"type": "data_exposure"}, [{"tool": "http_get", "args": {}, "result": {"status_code": 200, "body": "Welcome"}}])
    assert result["status"] == "FAILED" and "http_get" in result["evidence"]


def test_telnet_outcome_requires_structured_received_bytes():
    finding = {"type": "insecure_protocol", "service": "telnet", "port": 23}
    assert _tool_call_outcome({"tool": "telnet_connect", "result": json.dumps({"connected": True, "received_bytes": 0, "timed_out": True})}, finding) is False
    assert _tool_call_outcome({"tool": "telnet_connect", "result": json.dumps({"connected": True, "received_bytes": 8, "received_ascii": "uid=1"})}, finding) is True
