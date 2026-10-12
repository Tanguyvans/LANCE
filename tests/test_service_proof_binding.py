"""Offline service proofs must describe the executed target and protocol."""
import copy
import json
from threading import Event, Lock
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from src.agent.core.executor import wrap_tool
from src.agent.core.probes import (
    _COAP_GET_CORE_HEX, _ENIP_LIST_IDENTITY_HEX,
    _S7COMM_COTP_CR_HEX, _SNMP_V1_GET_SYS_DESCR_HEX,
)
from src.agent.evidence.capabilities import access_supported
from src.agent.exploit_evidence import synthesize_exploit_result
from src.agent.phases.verification.run import VerificationPhase
from src.agent.report_evidence import is_verified_report_finding


HOST = "192.0.2.10"
OTHER = "192.0.2.20"
# Complete responses to the repository's bounded discovery probes. These are
# read/negotiation proofs, not evidence of protected writes or machine access.
SNMP_REPLY = "302b02010004067075626c6963a21e0201010201000201003013301106082b0601020101010004056c696e7578"
COAP_REPLY = "64451234deadbeefff3c2f3e"
S7_REPLY = "0300001611d00001000200c1020100c2020102c0010a"
# Encapsulation + one identity item (version, socket, vendor/device/product,
# revision, status, serial, product-name length/name, state).
ENIP_ITEM = "01000002af12c000020a000000000000000001000c0001000101000001000000047465737403"
ENIP_REPLY = "63002c00000000000000000000000000000000000000000001000c002600" + ENIP_ITEM


def _binary_result(payload):
    return {"received_bytes": len(bytes.fromhex(payload)), "received_hex": payload}


def _case(service, kind, port, tool, args, result, *, protocol="tcp", endpoint=""):
    finding = {"id": "VULN-001", "device_id": "claimed", "device_ip": HOST,
               "service": service, "type": kind, "port": port,
               "protocol": protocol, "endpoint": endpoint, "severity": "HIGH"}
    return finding, {"tool": tool, "args": args, "result": result, "evidence_ref": "proof-1"}


CASES = [
    pytest.param(*_case("telnet", "insecure_protocol", 23, "telnet_connect",
        {"host": HOST, "port": 23},
        {"connected": True, "received_bytes": 6, "received_ascii": "Login:"}), id="telnet"),
    pytest.param(*_case("redis", "no_auth", 6379, "redis_cmd",
        {"host": HOST, "port": 6379, "command": "PING"},
        {"return_code": 0, "stdout": "PONG"}), id="redis"),
    pytest.param(*_case("ftp", "data_exposure", 21, "ftp_list",
        {"url": f"ftp://{HOST}:21/config/"},
        {"return_code": 0, "stdout": "-rw-r--r-- 1 root root 42 Jan 1 00:00 secrets.env"},
        endpoint="/config/"), id="ftp"),
    pytest.param(*_case("snmp", "default_credentials", 161, "udp_send",
        {"host": HOST, "port": 161, "payload": _SNMP_V1_GET_SYS_DESCR_HEX, "encoding": "hex"},
        _binary_result(SNMP_REPLY), protocol="udp"), id="snmp"),
    pytest.param(*_case("coap", "no_auth", 5683, "udp_send",
        {"host": HOST, "port": 5683, "payload": _COAP_GET_CORE_HEX, "encoding": "hex"},
        _binary_result(COAP_REPLY), protocol="udp"), id="coap"),
    pytest.param(*_case("s7comm", "no_auth", 102, "tcp_send",
        {"host": HOST, "port": 102, "payload_hex": _S7COMM_COTP_CR_HEX},
        _binary_result(S7_REPLY)), id="s7comm"),
    pytest.param(*_case("ethernet/ip", "no_auth", 44818, "tcp_send",
        {"host": HOST, "port": 44818, "payload_hex": _ENIP_LIST_IDENTITY_HEX},
        _binary_result(ENIP_REPLY)), id="enip"),
    pytest.param(*_case("redis", "default_credentials", 6379, "try_credential",
        {"ip": HOST, "port": 6379, "service": "redis", "user": "admin", "password": "admin"},
        {"success": True, "authenticated": True, "stdout": "+OK\n+PONG"}), id="credential"),
    pytest.param(*_case("https", "data_exposure", 8443, "http_get",
        {"url": f"https://{HOST}:8443/"},
        {"status_code": 200, "body": '{"password":"opaque-secret-123"}'}), id="http-without-endpoint"),
]


@pytest.mark.parametrize("finding,record", CASES)
@pytest.mark.parametrize("compact", [False, True], ids=["full", "compact"])
def test_matching_service_proofs_remain_accepted(finding, record, compact):
    result = synthesize_exploit_result(finding, [record], compact=compact)
    assert result["status"] == "EXPLOITED"
    assert result["device_ip"] == HOST and result["port"] == finding["port"]
    assert result["evidence_refs"] == ["proof-1"]


def _change_destination(record, *, host=None, port=None):
    args = record["args"]
    if "url" in args:
        scheme, remainder = args["url"].split("://", 1)
        _, path = remainder.split("/", 1)
        args["url"] = f"{scheme}://{host or HOST}:{port or (8443 if scheme == 'https' else 21)}/{path}"
    else:
        if host:
            args["ip" if "ip" in args else "host"] = host
        if port:
            args["port"] = port


@pytest.mark.parametrize("finding,record", CASES)
@pytest.mark.parametrize("mutation", ["host", "port", "transport", "service", "missing-args"])
def test_wrong_destination_or_service_cannot_confirm_a_real_claim(finding, record, mutation):
    finding, record = copy.deepcopy((finding, record))
    if mutation == "host":
        _change_destination(record, host=OTHER)
    elif mutation == "port":
        _change_destination(record, port=12345)
    elif mutation == "transport":
        finding["protocol"] = "tcp" if finding["protocol"] == "udp" else "udp"
    elif mutation == "service":
        finding["service"] = "mqtt"
    else:
        record["args"] = {}
    assert synthesize_exploit_result(finding, [record])["status"] != "EXPLOITED"


@pytest.mark.parametrize("finding,record", CASES[:8])
def test_runner_claim_metadata_does_not_override_executed_host(tmp_path, finding, record):
    finding, record = copy.deepcopy((finding, record))
    _change_destination(record, host=OTHER)
    run = SimpleNamespace(
        run_dir=tmp_path, _artifact_log_lock=Lock(), max_tool_calls=None, _tool_call_count=0,
        tracker=Mock(), _stop_event=Event(), benchmark_split="unassigned",
        context={"target_subnet": "192.0.2.0/24"},
        _exploit_tool_context=SimpleNamespace(vulnerability={
            "vuln_id": finding["id"], "device_ip": HOST, "port": finding["port"],
        }),
    )
    handler = Mock(return_value=json.dumps(record["result"]))
    wrapped = wrap_tool(run, {"name": record["tool"], "description": "offline probe", "function": handler},
                        phase=4, agent="proof-test")
    wrapped["function"](**record["args"])
    handler.assert_called_once_with(**record["args"])
    records = [json.loads(line) for line in (tmp_path / "tool_calls.jsonl").read_text().splitlines()]
    assert records[0]["execution_origin"] == "runner"
    assert records[0]["vuln_id"] == finding["id"]
    host = SimpleNamespace(_uses_compact_local_moe=lambda: False, _phase4_execution_errors={})
    verdict = VerificationPhase._resolve_exploit_verdict(host, finding, tmp_path / "unused.json", tool_records=records)
    assert verdict["status"] != "CONFIRMED"
    assert not is_verified_report_finding(verdict)


@pytest.mark.parametrize("index", [3, 4, 5, 6], ids=["snmp", "coap", "s7comm", "enip"])
@pytest.mark.parametrize("mutation", ["arbitrary-reply", "truncated-frame", "different-request", "wrong-tool", "wrong-result-host", "wrong-result-port"])
def test_raw_contact_needs_matching_protocol_exchange(index, mutation):
    finding, record = copy.deepcopy(CASES[index].values)
    if mutation == "arbitrary-reply":
        record["result"] = _binary_result("41434b")
    elif mutation == "truncated-frame":
        record["result"] = _binary_result(record["result"]["received_hex"][:8])
    elif mutation == "different-request":
        record["args"]["payload_hex" if record["tool"] == "tcp_send" else "payload"] = "00"
    elif mutation == "wrong-tool":
        record["tool"] = "udp_send" if record["tool"] == "tcp_send" else "tcp_send"
    elif mutation == "wrong-result-host":
        record["result"]["host"] = OTHER
    else:
        record["result"]["port"] = 12345
    assert synthesize_exploit_result(finding, [record])["status"] != "EXPLOITED"


@pytest.mark.parametrize("peer,accepted", [(f"{HOST}:5683", True), (f"{OTHER}:5683", False), (f"{HOST}:161", False), ("invalid", False)])
def test_udp_reply_peer_must_be_the_probed_destination(peer, accepted):
    finding, record = copy.deepcopy(CASES[4].values)
    record["result"]["peer"] = peer
    assert (synthesize_exploit_result(finding, [record])["status"] == "EXPLOITED") is accepted


@pytest.mark.parametrize("reply", [
    "64811234deadbeefff756e617574686f72697a6564",  # 4.01 Unauthorized
    "60451234",  # Empty ACK/token does not answer the request.
    "64459999deadbeefff3c2f3e",  # Other message ID.
    "6445123400000000ff3c2f3e",  # Other token.
    "64451234deadbeef",  # No returned discovery data.
])
def test_coap_denials_empty_ack_and_unrelated_replies_are_not_no_auth(reply):
    finding, record = copy.deepcopy(CASES[4].values)
    record["result"] = _binary_result(reply)
    assert synthesize_exploit_result(finding, [record])["status"] != "EXPLOITED"


@pytest.mark.parametrize("reply", [
    SNMP_REPLY.replace("a21e", "a01e"),  # GET request, not response.
    SNMP_REPLY.replace("020101020100", "020102020100"),  # Other request ID.
    SNMP_REPLY.replace("020101020100", "020101020105"),  # Error status.
    SNMP_REPLY.replace("7075626c6963", "707269766174"),  # Other community.
])
def test_snmp_requires_successful_public_response_to_the_requested_oid(reply):
    finding, record = copy.deepcopy(CASES[3].values)
    record["result"] = _binary_result(reply)
    assert synthesize_exploit_result(finding, [record])["status"] != "EXPLOITED"


@pytest.mark.parametrize("command,stdout,stderr,accepted", [
    ("PING", "PONG", "", True), ("PING", "+PONG\r\n", "", True),
    ("PING", "-NOAUTH Authentication required", "", False),
    ("PING", "PONG", "NOAUTH Authentication required", False),
    ("PING", "ERR unknown command", "", False), ("PING", "HTTP/1.1 200 OK", "", False),
    ("AUTH admin", "+OK", "", False), ("HELLO 3 AUTH admin admin", "server redis", "", False),
    ("GET secret", "password=opaque-secret-123", "", True),
])
def test_redis_needs_successful_unauthenticated_read_semantics(command, stdout, stderr, accepted):
    finding, record = copy.deepcopy(CASES[1].values)
    record["args"]["command"] = command
    record["result"].update(stdout=stdout, stderr=stderr)
    assert (synthesize_exploit_result(finding, [record])["status"] == "EXPLOITED") is accepted


@pytest.mark.parametrize("args,accepted", [
    ({"url": f"ftp://{HOST}:21/config/"}, True),
    ({"url": f"ftp://anonymous:@{HOST}:21/config/", "user": "anonymous:"}, True),
    ({"url": f"ftp://admin:admin@{HOST}:21/config/"}, False),
    ({"url": f"ftp://{HOST}:21/config/", "user": "admin:admin"}, False),
    ({"url": f"ftp://{HOST}:21/other/"}, False),
    ({"url": f"http://{HOST}:21/config/"}, False),
    ({"url": f"ftps://{HOST}:21/config/"}, False),
])
def test_ftp_sensitive_entries_require_matching_anonymous_listing(args, accepted):
    finding, record = copy.deepcopy(CASES[2].values)
    record["args"] = args
    assert (synthesize_exploit_result(finding, [record])["status"] == "EXPLOITED") is accepted


@pytest.mark.parametrize("kind", ["no_auth", "insecure_protocol"])
def test_plain_ftp_listing_supports_its_access_and_transport_properties(kind):
    finding, record = copy.deepcopy(CASES[2].values)
    finding["type"] = kind
    record["args"]["url"] = f"ftp://anonymous:@{HOST}/config/"
    record["result"]["stdout"] = "-rw-r--r-- 1 root root 42 Jan 1 00:00 firmware.bin"
    assert synthesize_exploit_result(finding, [record])["status"] == "EXPLOITED"
    finding["type"] = "data_exposure"
    assert synthesize_exploit_result(finding, [record])["status"] != "EXPLOITED"


@pytest.mark.parametrize("reply,accepted", [
    ({"received_ascii": "Login:"}, True), ({"received_ascii": "uid=0(root)"}, True),
    ({"received_hex": "fffb01"}, True), ({"received_ascii": "HTTP/1.1 200 OK"}, False),
    ({"received_ascii": "ACK"}, False),
])
def test_telnet_needs_protocol_or_identity_reply(reply, accepted):
    finding, record = copy.deepcopy(CASES[0].values)
    received_count = len(bytes.fromhex(reply["received_hex"])) if "received_hex" in reply else len(reply["received_ascii"])
    record["result"] = {"connected": True, "received_bytes": received_count, **reply}
    assert (synthesize_exploit_result(finding, [record])["status"] == "EXPLOITED") is accepted


@pytest.mark.parametrize("index", [0, 1, 2, 3, 4, 5, 6])
def test_same_service_on_explicit_nonstandard_port_is_not_rejected(index):
    finding, record = copy.deepcopy(CASES[index].values)
    finding["port"] = 12345
    _change_destination(record, port=12345)
    assert synthesize_exploit_result(finding, [record])["status"] == "EXPLOITED"


@pytest.mark.parametrize("index", [0, 1, 2, 3, 4, 5, 6, 7, 8])
@pytest.mark.parametrize("port", [True, 0, 65536, "invalid"])
def test_invalid_port_claim_never_inherits_valid_target_evidence(index, port):
    finding, record = copy.deepcopy(CASES[index].values)
    finding["port"] = port
    assert synthesize_exploit_result(finding, [record])["status"] != "EXPLOITED"


@pytest.mark.parametrize("index", [0, 1, 7])
def test_tool_default_port_remains_bound_to_the_actual_claim(index):
    finding, record = copy.deepcopy(CASES[index].values)
    record["args"].pop("port")
    assert synthesize_exploit_result(finding, [record])["status"] == "EXPLOITED"
    finding["port"] = 12345
    assert synthesize_exploit_result(finding, [record])["status"] != "EXPLOITED"


def test_http_scheme_is_bound_even_when_endpoint_is_absent():
    finding, record = copy.deepcopy(CASES[8].values)
    record["args"]["url"] = f"http://{HOST}:8443/"
    assert synthesize_exploit_result(finding, [record])["status"] != "EXPLOITED"


@pytest.mark.parametrize("field", ["stderr", "interpretation"])
def test_ftp_model_annotations_and_diagnostics_cannot_supply_sensitive_entries(field):
    finding, record = copy.deepcopy(CASES[2].values)
    record["result"] = {"return_code": 0, "stdout": "firmware.bin", field: "config secret backup password"}
    assert synthesize_exploit_result(finding, [record])["status"] != "EXPLOITED"


@pytest.mark.parametrize("index", [0, 1, 2, 3, 4, 5, 6])
@pytest.mark.parametrize("marker", ["timed_out", "cancelled"])
def test_interrupted_probe_is_not_a_confirmed_property(index, marker):
    finding, record = copy.deepcopy(CASES[index].values)
    record["result"][marker] = True
    assert synthesize_exploit_result(finding, [record])["status"] != "EXPLOITED"


def test_enip_service_alias_keeps_its_valid_identity_proof():
    finding, record = copy.deepcopy(CASES[6].values)
    finding["service"] = "enip"
    assert synthesize_exploit_result(finding, [record])["status"] == "EXPLOITED"


def test_coap_discovery_supports_existing_misconfiguration_plan():
    finding, record = copy.deepcopy(CASES[4].values)
    finding["type"] = "misconfiguration"
    assert synthesize_exploit_result(finding, [record])["status"] == "EXPLOITED"


@pytest.mark.parametrize("rc", [True, False, 1, 124])
def test_telnet_reply_cannot_override_invalid_exit_status(rc):
    finding, record = copy.deepcopy(CASES[0].values)
    record["result"]["return_code"] = rc
    assert synthesize_exploit_result(finding, [record])["status"] != "EXPLOITED"


@pytest.mark.parametrize("service,output", [
    ("telnet", {"stdout": "uid=0(root)"}),
    ("redis", {"stdout": "+OK\n+PONG"}),
    ("ftp", {"stdout": "welcome", "anonymous_access": False}),
    ("http", {"unauthenticated_http_code": "401", "http_code": "200"}),
    ("mysql", {"stdout": "user\thost\nadmin\t%\n"}),
])
@pytest.mark.parametrize("contradiction", [
    {"return_code": 1}, {"return_code": True}, {"return_code": False},
    {"cancelled": True}, {"timed_out": True}, {"error": "synthetic transport error"}, {"ok": False},
])
def test_credential_success_flags_cannot_override_failed_or_interrupted_execution(service, output, contradiction):
    record = {"tool": "try_credential", "args": {"service": service},
              "result": {"success": True, "authenticated": True, **output, **contradiction}}
    assert not access_supported(record)
    assert synthesize_exploit_result({"type": "default_credentials"}, [record])["status"] != "EXPLOITED"
