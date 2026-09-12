"""Independent MQTT topic attribution checks through Phase 4 and scoring."""
import copy
import json
from types import SimpleNamespace

import pytest

from src.agent.exploit_evidence import synthesize_exploit_result
from src.agent.phases.verification.evidence import _make_test_entry
from src.agent.phases.verification.run import VerificationPhase
from src.agent.core.executor import wrap_tool
from tests.test_mqtt_execution_boundary import boundary
from tests.test_evaluation_audit import _confirmed, _evaluate, _finding, _truth


TOPIC = "smartcity/admin/credentials"
SECRET = "password=synthetic-secret"


def finding(**changes):
    return _finding(**{"type": "data_exposure", "service": "mqtt", "port": 1883,
                       "endpoint": TOPIC, "details": "Credentials in a specific MQTT topic",
                       **changes})


def record(messages=None, subscription="#", **output):
    if messages is None:
        messages = [("sensors/temp", "22"), (TOPIC, SECRET)]
    return {
        "tool": "mqtt_listen", "vuln_id": "V1", "evidence_ref": "proof-V1",
        "args": {"broker": "192.0.2.1", "port": 1883, "topic": subscription},
        "result": {
            "stdout": "".join(json.dumps({"tst": "fixture", "topic": t, "payload": p,
                                         "qos": 0, "retain": 0,
                                         "payloadlen": len(p.encode("utf-8"))}) + "\n" for t, p in messages),
            "stderr": "", "return_code": 0,
            "execution_attestation": {"protocol": "TCP", "host": "192.0.2.1",
                                      "port": 1883, "topic": subscription,
                                      "output_format": "mosquitto-json-v1"},
            **output,
        },
    }


def evaluated(tmp_path, v, r, test=None):
    gt = _truth(category=v["type"], accepted_types=[v["type"]], services=["mqtt"],
                ports=[v["port"]], endpoints=[v["endpoint"]] if v["endpoint"] else [])
    return _evaluate(tmp_path, [v], [gt], tests=[test or _confirmed(v, "mqtt_listen")], records=[r])


@pytest.mark.parametrize("compact", [False, True])
@pytest.mark.parametrize("code", [0, 27])
@pytest.mark.parametrize("subscription", ["#", "smartcity/#", "smartcity/+/credentials", TOPIC])
def test_received_primary_topic_is_valid_in_both_profiles(tmp_path, compact, code, subscription):
    v = finding()
    r = record([(TOPIC, SECRET)], subscription, return_code=code)
    if code == 27:
        r["result"]["stderr"] = "Timed out"
    path = tmp_path / "exploit.json"
    path.write_text(json.dumps({"status": "FAILED", "evidence_level": 1}))
    verdict = VerificationPhase._resolve_exploit_verdict(
        SimpleNamespace(_uses_compact_local_moe=lambda: compact), v, path, tool_records=[r])
    assert verdict["status"] == "CONFIRMED"
    entry = _make_test_entry(v, status=verdict["status"], result=verdict)
    result = evaluated(tmp_path, v, r, entry)
    assert result.funnel["stages"]["confirmed"]["true_positives"] == 1
    assert result.funnel["stages"]["confirmed"]["false_negatives"] == 0


@pytest.mark.parametrize("messages", [
    [("sensors/temp", SECRET)],
    [("Smartcity/admin/credentials", SECRET)],
    [(TOPIC + "/other", SECRET)],
    [("sensors/temp", TOPIC + " " + SECRET)],
    [("sensors/temp", "22\n" + TOPIC + " " + SECRET)],
    [("sensors/temp", json.dumps({"topic": TOPIC, "payload": SECRET}))],
    [(TOPIC, "no sensitive value here"), ("unrelated/topic", SECRET)],
    [],
])
def test_unrelated_payloads_cannot_prove_the_primary_topic(tmp_path, messages):
    v, r = finding(), record(messages)
    assert synthesize_exploit_result(v, [r])["status"] != "EXPLOITED"
    assert evaluated(tmp_path, v, r).funnel["stages"]["confirmed"]["true_positives"] == 0


@pytest.mark.parametrize("section,changes", [
    ("args", {"broker": "192.0.2.2"}), ("args", {"port": 1884}),
    ("args", {"port": True}), ("args", {"topic": "sensors/#"}),
    ("attestation", {"host": "192.0.2.2"}), ("attestation", {"port": 1884}),
    ("attestation", {"protocol": "WebSocket"}), ("attestation", {"topic": "sensors/#"}),
    ("attestation", {"output_format": "unframed"}),
])
def test_requested_and_effective_target_must_agree(tmp_path, section, changes):
    v, r = finding(), record()
    target = r["args"] if section == "args" else r["result"]["execution_attestation"]
    target.update(changes)
    assert synthesize_exploit_result(v, [r])["status"] != "EXPLOITED"
    assert evaluated(tmp_path, v, r).funnel["stages"]["confirmed"]["true_positives"] == 0


@pytest.mark.parametrize("output", [
    {"return_code": 5}, {"return_code": 1}, {"success": False}, {"error": "refused"},
    {"stdout": "", "return_code": 27, "interpretation": "anonymous_access_confirmed_broker_idle"},
    {"stdout": '{"topic":"sensors/temp","topic":"smartcity/admin/credentials","payload":"password=fixture"}\n'},
    {"stdout": '{"topic":"smartcity/admin/credentials","payload":'},
    {"stdout": "[]\n"},
    {"stdout": json.dumps({"topic": TOPIC, "payload": {"password": "fixture"}}) + "\n"},
])
def test_errors_and_malformed_frames_are_not_topic_proof(tmp_path, output):
    v, r = finding(), record(**output)
    assert synthesize_exploit_result(v, [r])["status"] != "EXPLOITED"
    assert evaluated(tmp_path, v, r).funnel["stages"]["confirmed"]["true_positives"] == 0


@pytest.mark.parametrize("field,value", [("vuln_id", "V2"), ("evidence_ref", "other"), ("tool", "http_get")])
def test_wildcard_does_not_relax_reference_ownership(tmp_path, field, value):
    r = record()
    r[field] = value
    assert evaluated(tmp_path, finding(), r).funnel["stages"]["confirmed"]["true_positives"] == 0


@pytest.mark.parametrize("structured", [False, True])
def test_historical_unframed_stdout_is_not_promoted(structured):
    r = record()
    del r["result"]["execution_attestation"]
    if not structured:
        r["result"]["stdout"] = f"sensors/temp 22\n{TOPIC} {SECRET}\n"
    assert synthesize_exploit_result(finding(), [r])["status"] != "EXPLOITED"


def test_matching_topic_payload_is_preserved_without_other_topics():
    v, r = finding(), record()
    original = copy.deepcopy(r)
    result = synthesize_exploit_result(v, [r])
    assert result["status"] == "EXPLOITED"
    assert SECRET in result["evidence"]
    assert "sensors/temp" not in result["evidence"]
    assert r == original


def test_sensitive_looking_topic_name_is_not_sensitive_payload():
    v = finding(endpoint="password=synthetic-secret")
    r = record([(v["endpoint"], "public temperature")])
    assert synthesize_exploit_result(v, [r])["status"] != "EXPLOITED"


def test_secondary_topic_does_not_replace_primary():
    v = finding(endpoints=[TOPIC, "unrelated/topic"])
    assert synthesize_exploit_result(v, [record([("unrelated/topic", SECRET)])])["status"] != "EXPLOITED"


@pytest.mark.parametrize("port", ["1883", "01883"])
def test_original_string_port_matches_integer_execution_attestation(tmp_path, port):
    r = record()
    r["args"]["port"] = port
    assert synthesize_exploit_result(finding(), [r])["status"] == "EXPLOITED"
    assert evaluated(tmp_path, finding(), r).funnel["stages"]["confirmed"]["true_positives"] == 1


def test_missing_port_and_topic_use_the_executed_defaults():
    r = record()
    del r["args"]["port"]
    del r["args"]["topic"]
    assert synthesize_exploit_result(finding(), [r])["status"] == "EXPLOITED"


def test_unicode_line_separator_is_payload_not_a_new_message():
    r = record([(TOPIC, SECRET + "\u2028extra")])
    r["result"]["stdout"] = r["result"]["stdout"].replace("\\u2028", "\u2028")
    assert synthesize_exploit_result(finding(), [r])["status"] == "EXPLOITED"


@pytest.mark.parametrize("topic", [TOPIC, ""])
def test_bad_framing_marker_never_falls_back_to_legacy_text(topic):
    r = record(subscription=TOPIC)
    r["result"]["stdout"] = f"{TOPIC} {SECRET}\n"
    assert synthesize_exploit_result(finding(endpoint=topic), [r])["status"] != "EXPLOITED"


def test_real_executor_ledger_can_support_a_wildcard_proof(boundary):
    run, tool, launcher = boundary
    v = finding(device_ip="192.0.2.11")
    run._exploit_tool_context.vulnerability = {"vuln_id": "V1", "device_ip": v["device_ip"], "port": 1883}
    raw = record()["result"]["stdout"]
    launcher.return_value = {"stdout": raw, "stderr": "Timed out", "return_code": 27}
    requested = {"broker": v["device_ip"], "port": "1883", "topic": "#"}
    receipt = json.loads(wrap_tool(run, tool, phase=4)["function"](**requested))
    archived, = [json.loads(line) for line in (run.run_dir / "tool_calls.jsonl").read_text().splitlines()]
    assert archived["args"] == requested
    assert json.loads(archived["result"])["stdout"] == raw == receipt["stdout"]
    assert synthesize_exploit_result(v, [archived])["status"] == "EXPLOITED"


@pytest.mark.parametrize("kind,subscription,messages", [
    ("no_auth", "#", [("sensors/temp", "22")]),
    ("data_exposure", "#", [(TOPIC, SECRET)]),
    ("info_disclosure", "$SYS/#", [("$SYS/broker/version", "mosquitto version 2.0.21")]),
])
def test_generic_claims_without_topic_keep_valid_message_proofs(tmp_path, kind, subscription, messages):
    v, r = finding(type=kind, endpoint=""), record(messages, subscription)
    result = synthesize_exploit_result(v, [r])
    assert result["status"] == "EXPLOITED"
    assert all(isinstance(value, str) for value in result["data_extracted"])
    assert evaluated(tmp_path, v, r).funnel["stages"]["confirmed"]["true_positives"] == 1
