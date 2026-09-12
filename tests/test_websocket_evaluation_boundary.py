"""Independent transport/application regressions through the actual evaluator."""
import json
from types import SimpleNamespace

import pytest

from src.agent.phases.verification.run import VerificationPhase
from src.agent.phases.verification.evidence import _make_test_entry
from src.agent.phases.verification.contract import _phase4_verification_plan
from src.agent.exploit_evidence import synthesize_exploit_result
from src.benchmark.evaluator import _run_metric_contract_status
from src.benchmark.metric_contract import EVIDENCE_CONTRACT_VERSION, METRIC_CONTRACT_VERSION
from tests.test_evaluation_audit import _confirmed, _evaluate, _finding, _truth


def ws_finding(kind="no_auth", **changes):
    return _finding(**{"type": kind, "service": "mqtt-ws", "port": 9001,
                       "endpoint": "/", "details": "MQTT over WebSocket", **changes})


def upgrade_record(**result_changes):
    return {
        "tool": "http_request", "vuln_id": "V1", "evidence_ref": "proof-V1",
        "args": {"url": "http://192.0.2.1:9001/", "method": "GET", "headers": {
            "Connection": "Upgrade", "Upgrade": "websocket",
            "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
        }},
        "result": {"status_code": 101, "body": "", "headers": {
            "Connection": "Upgrade", "Upgrade": "WebSocket",
            "Sec-WebSocket-Accept": "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
        }, **result_changes},
    }


def evaluated(tmp_path, finding, record):
    truth = _truth(category=finding["type"], accepted_types=[finding["type"]],
                   services=["mqtt-ws"], ports=[9001], endpoints=["/"])
    return _evaluate(tmp_path, [finding], [truth],
                     tests=[_confirmed(finding, "http_request")], records=[record])


@pytest.mark.parametrize("kind", ["no_auth", "data_exposure"])
@pytest.mark.parametrize("response", [{}, {"status_code": 200, "body": "admin dashboard token=fixture-secret"},
                                      {"status_code": None, "success": True, "return_code": 0}])
def test_http_transport_never_earns_mqtt_application_credit(tmp_path, kind, response):
    result = evaluated(tmp_path, ws_finding(kind), upgrade_record(**response))
    assert result.funnel["stages"]["candidates"]["true_positives"] == 1
    confirmed = result.funnel["stages"]["confirmed"]
    assert confirmed["true_positives"] == 0
    assert confirmed["false_negatives"] == 1
    assert confirmed["invalid_evidence"] == 1


def test_observed_upgrade_can_still_prove_transport_exposure(tmp_path):
    result = evaluated(tmp_path, ws_finding("network_exposure"), upgrade_record())
    assert result.funnel["stages"]["confirmed"]["true_positives"] == 1


@pytest.mark.parametrize("alias", ["mqtt-ws", "mqtt_websocket", "mqtt-websocket", "mqttws", "websocket", "ws"])
@pytest.mark.parametrize("kind,expected", [("no_auth", 0), ("network_exposure", 1)])
def test_evaluator_and_validator_agree_on_service_aliases(tmp_path, alias, kind, expected):
    result = evaluated(tmp_path, ws_finding(kind, service=alias), upgrade_record())
    assert result.funnel["stages"]["confirmed"]["true_positives"] == expected


@pytest.mark.parametrize("url", ["http://192.0.2.2:9001/", "http://192.0.2.1:9002/",
                                "http://192.0.2.1:9001/other"])
def test_transport_proof_keeps_exact_destination(tmp_path, url):
    record = upgrade_record()
    record["args"]["url"] = url
    result = evaluated(tmp_path, ws_finding("network_exposure"), record)
    assert result.funnel["stages"]["confirmed"]["true_positives"] == 0


@pytest.mark.parametrize("final_url", ["http://192.0.2.2:9001/", "http://192.0.2.1:9002/",
                                      "http://192.0.2.1:9001/other"])
def test_redirect_cannot_prove_the_original_websocket_target(tmp_path, final_url):
    result = evaluated(tmp_path, ws_finding("network_exposure"),
                       upgrade_record(final_url=final_url))
    assert result.funnel["stages"]["confirmed"]["true_positives"] == 0


@pytest.mark.parametrize("response", [
    {"status_code": 101.5},
    {"headers": None, "body": "Upgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Accept: forged"},
    {"headers": None, "interpretation": "Upgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Accept: forged"},
    {"headers": None, "body": "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"},
    {"headers": {"Upgrade": "websocket"}},
    {"headers": {"Upgrade": "websocket", "Connection": "Upgrade", "Sec-WebSocket-Accept": "wrong-key"}},
])
def test_only_actual_complete_response_headers_support_transport(tmp_path, response):
    result = evaluated(tmp_path, ws_finding("network_exposure"), upgrade_record(**response))
    assert result.funnel["stages"]["confirmed"]["true_positives"] == 0


@pytest.mark.parametrize("headers", ["not-an-object", ["Upgrade"], 1, True])
def test_malformed_recorded_request_headers_fail_closed(tmp_path, headers):
    record = upgrade_record()
    record["args"]["headers"] = headers
    result = evaluated(tmp_path, ws_finding("network_exposure"), record)
    assert result.funnel["stages"]["confirmed"]["true_positives"] == 0


@pytest.mark.parametrize("compact", [False, True])
@pytest.mark.parametrize("kind", ["no_auth", "data_exposure"])
def test_pipeline_overrules_model_confirmation_in_both_profiles(tmp_path, compact, kind):
    finding = ws_finding(kind)
    path = tmp_path / "result.json"
    path.write_text(json.dumps(_confirmed(finding, "http_request")))
    phase = SimpleNamespace(_uses_compact_local_moe=lambda: compact)
    verdict = VerificationPhase._resolve_exploit_verdict(
        phase, finding, path, tool_records=[upgrade_record()])
    assert verdict["status"] not in {"CONFIRMED", "EXPLOITED", "COMPROMISED"}
    assert verdict["evidence_level"] < 2
    entry = _make_test_entry(finding, status=verdict["status"], result=verdict)
    assert entry["verification_status"] == "inconclusive"
    truth = _truth(category=kind, accepted_types=[kind], services=["mqtt-ws"],
                   ports=[9001], endpoints=["/"])
    evaluation = _evaluate(tmp_path, [finding], [truth], tests=[entry],
                           records=[upgrade_record()])
    assert evaluation.funnel["stages"]["filtered"]["true_positives"] == 1
    confirmed = evaluation.funnel["stages"]["confirmed"]
    assert confirmed["true_positives"] == confirmed["false_positives"] == 0
    assert confirmed["false_negatives"] == 1
    assert evaluation.funnel["diagnostics"]["verification_attempt_rate"] == 1


def test_previous_contract_is_not_silently_reinterpreted(tmp_path):
    path = tmp_path / "run_meta.json"
    previous = json.dumps({"metric_contract_version": METRIC_CONTRACT_VERSION,
                           "evidence_contract_version": "evidence-v8"})
    path.write_text(previous)
    _, version, compatible, reason = _run_metric_contract_status(tmp_path)
    assert EVIDENCE_CONTRACT_VERSION != "evidence-v8"
    assert version == "evidence-v8" and not compatible
    assert "evidence" in reason
    assert path.read_text() == previous


@pytest.mark.parametrize("alias", ["mqtt-ws", "mqtt_websocket", "mqtt-websocket", "mqttws", "websocket", "ws"])
@pytest.mark.parametrize("port", [1883, 9002])
def test_tcp_messages_never_prove_websocket_on_nonstandard_ports(alias, port):
    finding = ws_finding(service=alias, port=port, endpoint="")
    verdict = synthesize_exploit_result(finding, [{
        "tool": "mqtt_listen", "args": {"broker": "192.0.2.1", "port": port, "topic": "#"},
        "result": {"return_code": 0, "stdout": "sensors/temp 24"},
    }])
    assert _make_test_entry(finding, status=verdict["status"], result=verdict)["verification_status"] == "inconclusive"


def test_generic_http_on_9001_keeps_its_own_application_contract():
    finding = ws_finding(service="http")
    plan = _phase4_verification_plan(finding)
    assert "Sec-WebSocket-Key" not in plan.get("args_hint", {}).get("headers", {})
    verdict = synthesize_exploit_result(finding, [upgrade_record(
        status_code=200, headers={}, body="Admin dashboard devices configuration")])
    assert verdict["status"] == "EXPLOITED"
