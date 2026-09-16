"""Focused MQTT-over-WebSocket producer, proof, and routing checks."""
from __future__ import annotations

import json
import base64
import sys
import threading
import time
from types import ModuleType, SimpleNamespace

import pytest

from src.agent.evidence.mqtt_ws import trusted_mqtt_ws_messages
from src.agent.exploit_evidence import synthesize_exploit_result
from src.agent.phases.verification.contract import (
    PHASE4_LOCAL_SERVICE_TOOL_NAMES,
    _phase4_local_verification_tools,
    _phase4_requirement_matches,
    _phase4_verification_plan,
)
from src.agent.tools.mqtt_ws import mqtt_ws_listen
from src.agent.tools.recon_tools import RECON_TOOLS
from src.agent.execution_profiles import COMPACT_PHASE_TOOL_NAMES, EXECUTION_PROFILES, filter_profile_tools
from src.benchmark.evaluator import _tool_call_matches_finding, _tool_call_outcome


IP = "127.0.0.1"
PATH = "/mqtt"
TOPIC = "sensors/temperature"


def _message(payload: str = "22.5") -> dict:
    return {
        "topic": TOPIC,
        "payload": payload,
        "payload_b64": base64.b64encode(payload.encode()).decode(),
        "payload_length": len(payload.encode()),
        "raw_payload_complete": True,
        "raw_topic_complete": True,
        "qos": 0,
        "retain": True,
        "captured_at": "2026-09-16T00:00:00+00:00",
    }


def _result(**changes) -> dict:
    result = {
        "ok": True,
        "success": True,
        "status": "success",
        "return_code": 0,
        "timed_out": False,
        "partial_timeout": False,
        "error": None,
        "output_truncated": False,
        "connack": {"received": True, "reason_code": 0, "accepted": True},
        "suback": {
            "received": True, "mid": 7, "reason_codes": [0],
            "requested_qos": [0], "granted_qos": [0],
            "mid_matches_request": True, "accepted": True,
        },
        "subscribe_mid": 7,
        "messages": [_message()],
        "received_count": 1,
        "requested_count": 1,
        "execution_attestation": {
            "output_format": "mqtt-ws-json-v1", "protocol": "MQTTv311",
            "transport": "websockets", "ip": IP, "host": IP, "port": 9001,
            "path": PATH, "topic": TOPIC, "no_auth": True, "auth": "no_auth",
            "clean_session": True, "reconnect_on_failure": False,
        },
    }
    result.update(changes)
    return result


def _args(**changes) -> dict:
    return {"ip": IP, "port": 9001, "path": PATH, "topic": TOPIC,
            "count": 1, "timeout": 1, **changes}


def _finding(**changes) -> dict:
    return {"id": "V1", "type": "no_auth", "service": "mqtt-ws",
            "device_ip": IP, "port": 9001, "endpoint": PATH, "topic": TOPIC,
            "tool_used": "mqtt_ws_listen", "evidence_refs": ["tc-ws"], **changes}


def _fake_paho(monkeypatch, *, messages=1, delay=0.0, auth=False, drip=False):
    fake = ModuleType("paho.mqtt.client")

    class Reason:
        VERSION2 = 2

    class Message:
        def __init__(self, payload):
            self.topic, self.payload, self.qos, self.retain = TOPIC, payload.encode(), 0, True

    class Client:
        instances = []

        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.on_connect = self.on_subscribe = self.on_message = None
            self.delivered = 0
            self.closed = False
            self.__class__.instances.append(self)

        def ws_set_options(self, *, path, headers=None):
            self.ws_path, self.ws_headers = path, headers

        def connect(self, ip, port, keepalive):
            self.connect_args = (ip, port, keepalive)
            if auth:
                self.on_connect(self, None, {}, auth if isinstance(auth, int) else 5, None)
            else:
                self.on_connect(self, None, {}, 0, None)

        def subscribe(self, topic, qos):
            self.subscription = (topic, qos)
            return 0, 7

        def loop(self, timeout):
            if drip:
                time.sleep(min(0.02, timeout))
                return 0
            if self.delivered == 0:
                self.on_subscribe(self, None, 7, [0], None)
            if self.delivered < messages:
                self.on_message(self, None, Message(str(22 + self.delivered)))
                self.delivered += 1
            if delay:
                time.sleep(delay)
            return 0

        def disconnect(self):
            self.closed = True

        def _sock_close(self):
            self.closed = True

    fake.Client = Client
    fake.CallbackAPIVersion = Reason
    fake.MQTTv311 = 4
    import paho.mqtt as paho_mqtt
    monkeypatch.setitem(sys.modules, "paho.mqtt.client", fake)
    monkeypatch.setattr(paho_mqtt, "client", fake, raising=False)
    return Client


def test_registered_tool_schema_is_closed_and_handler_is_present():
    tool = next(item for item in RECON_TOOLS if item["name"] == "mqtt_ws_listen")
    assert tool["function"] is mqtt_ws_listen
    assert tool["input_schema"]["additionalProperties"] is False
    assert tool["input_schema"]["required"] == ["ip", "port", "path", "topic"]


def test_producer_uses_anonymous_paho_websocket_exchange(monkeypatch):
    Client = _fake_paho(monkeypatch)
    result = json.loads(mqtt_ws_listen(**_args()))
    assert result["status"] == "success"
    assert result["connack"]["reason_code"] == 0
    assert result["suback"]["reason_codes"] == [0]
    assert result["messages"][0]["payload"] == "22"
    assert result["execution_attestation"]["transport"] == "websockets"
    assert Client.instances[0].kwargs["callback_api_version"] == 2
    assert Client.instances[0].kwargs["clean_session"] is True
    assert Client.instances[0].kwargs["reconnect_on_failure"] is False
    assert Client.instances[0].ws_headers is None
    assert Client.instances[0].closed is True


@pytest.mark.parametrize("bad", [
    {"ip": "broker.local"}, {"ip": "http://127.0.0.1"},
    {"port": 0}, {"port": 65536}, {"path": "http://127.0.0.1/mqtt"},
    {"path": "/mqtt?x=1"}, {"path": "/mqtt\r\nX-Evil: 1"},
    {"topic": "sensors/#/bad"}, {"count": 0}, {"timeout": 61},
])
def test_invalid_args_are_refused_before_paho_import_or_network(monkeypatch, bad):
    monkeypatch.setattr("src.agent.tools.mqtt_ws.get_tool_stop_event", lambda: None)
    called = {"value": False}
    real_import = __import__

    def guarded_import(*args, **kwargs):
        if args and args[0] == "paho.mqtt.client":
            called["value"] = True
        return real_import(*args, **kwargs)

    monkeypatch.setattr("builtins.__import__", guarded_import)
    result = json.loads(mqtt_ws_listen(**_args(**bad)))
    assert result["error_kind"] == "invalid_tool_arguments"
    assert called["value"] is False


def test_real_proof_requires_exact_connack_suback_and_publication():
    args = _args()
    good = _result()
    assert trusted_mqtt_ws_messages(good, args, IP, 9001, PATH, TOPIC)
    for change in (
        {"execution_attestation": {**good["execution_attestation"], "transport": "tcp"}},
        {"connack": {"received": True, "reason_code": 5, "accepted": True}},
        {"suback": {**good["suback"], "reason_codes": [1]}},
        {"messages": []}, {"status": "success", "success": False},
        {"status": "success", "error": "late network error"},
        {"output_truncated": True}, {"messages": [_message() | {"payload_b64": "bad"}]},
        {"messages": [_message(), {"malformed": True}]},
    ):
        assert not trusted_mqtt_ws_messages({**good, **change}, args, IP, 9001, PATH, TOPIC)


def test_requested_topic_must_equal_claim_topic_in_both_verifiers():
    finding = _finding()
    record = {"tool": "mqtt_ws_listen", "vuln_id": "V1", "_evidence_ref": "tc-ws",
              "args": _args(topic="#"), "result": _result()}
    assert not trusted_mqtt_ws_messages(record["result"], record["args"], IP, 9001, PATH, TOPIC)
    assert not _tool_call_matches_finding(finding, record)
    assert synthesize_exploit_result(finding, [record])["status"] != "EXPLOITED"


@pytest.mark.parametrize("bad_port", [0, 65536, True, 9001.5])
def test_invalid_finding_port_cannot_match_ws_proof(bad_port):
    finding = _finding(port=bad_port)
    record = {"tool": "mqtt_ws_listen", "vuln_id": "V1", "_evidence_ref": "tc-ws",
              "args": _args(), "result": _result()}
    assert not _tool_call_matches_finding(finding, record)
    assert synthesize_exploit_result(finding, [record])["status"] != "EXPLOITED"


def test_auth_required_uses_paho_not_authorized_code(monkeypatch):
    _fake_paho(monkeypatch, auth=135)
    result = json.loads(mqtt_ws_listen(**_args()))
    assert result["status"] == "auth_required"
    assert result["connack"]["reason_code"] == 135
    assert result["success"] is False


def test_partial_timeout_is_explicit_but_still_uses_real_exchange(monkeypatch):
    _fake_paho(monkeypatch, messages=1)
    result = json.loads(mqtt_ws_listen(**_args(count=2, timeout=1)))
    assert result["status"] == "timeout"
    assert result["timed_out"] is True
    assert result["partial_timeout"] is True
    assert result["success"] is True


def test_http101_and_plain_tcp_never_prove_mqtt_ws():
    finding = _finding()
    record = {"tool": "mqtt_listen", "args": {"broker": IP, "port": 9001, "topic": TOPIC},
              "result": {"return_code": 0, "stdout": f"{TOPIC} 22"}}
    assert synthesize_exploit_result(finding, [record])["status"] != "EXPLOITED"
    http = {"tool": "http_request", "args": {"url": f"http://{IP}:9001/mqtt"},
            "result": {"status_code": 101, "headers": {"Upgrade": "websocket"}}}
    assert synthesize_exploit_result(finding, [http])["status"] != "EXPLOITED"


def test_attribution_wrong_target_path_topic_and_successful_outcome():
    finding = _finding()
    record = {"tool": "mqtt_ws_listen", "vuln_id": "V1", "_evidence_ref": "tc-ws",
              "args": _args(), "result": _result()}
    assert _tool_call_matches_finding(finding, record)
    assert _tool_call_outcome(record, finding) is True
    for bad in ("ip", "path", "topic", "port"):
        changed = dict(record["args"])
        changed[bad] = {"ip": "127.0.0.2", "path": "/other", "topic": "other", "port": 9002}[bad]
        assert not _tool_call_matches_finding(finding, {**record, "args": changed})


@pytest.mark.parametrize("change", [
    {"endpoint": "http://evil.example:9001/mqtt"},
    {"endpoint": "/mqtt", "path": "/other"},
    {"topic": TOPIC, "mqtt_topic": "other"},
])
def test_malformed_or_conflicting_ws_claims_cannot_donate_proof(change):
    finding = _finding(**change)
    record = {"tool": "mqtt_ws_listen", "vuln_id": "V1", "_evidence_ref": "tc-ws",
              "args": _args(), "result": _result()}
    assert not _tool_call_matches_finding(finding, record)
    assert synthesize_exploit_result(finding, [record])["status"] != "EXPLOITED"


def test_planner_and_full_compact_scope_use_dedicated_tool_only():
    finding = _finding()
    requirement = _phase4_verification_plan(finding)
    assert requirement["tool"] == "mqtt_ws_listen"
    assert _phase4_requirement_matches(requirement, "mqtt_ws_listen", requirement["args_hint"])
    assert not _phase4_requirement_matches(requirement, "mqtt_ws_listen", {**requirement["args_hint"], "topic": "wrong"})
    tools = [{"name": name} for name in ("mqtt_ws_listen", "http_request", "mqtt_listen")]
    scoped = _phase4_local_verification_tools(tools, category="data_access", service="mqtt-ws")
    assert {tool["name"] for tool in scoped} == {"mqtt_ws_listen", "http_request"}
    assert "mqtt_ws_listen" in COMPACT_PHASE_TOOL_NAMES[5]
    assert "mqtt_ws_listen" in {tool["name"] for tool in filter_profile_tools(EXECUTION_PROFILES["compact"], 5, tools)}
    assert {"http_request", "http_get", "curl_headers"} <= PHASE4_LOCAL_SERVICE_TOOL_NAMES["mqtt-ws"]
