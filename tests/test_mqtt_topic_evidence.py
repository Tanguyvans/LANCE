"""Focused unit coverage for framed MQTT topic attribution."""
import json

from src.agent.evidence.mqtt import (
    MQTTFramingError,
    mqtt_topic_matches,
    parse_json_lines,
    select_mqtt_messages,
    trusted_mqtt_messages,
)
from src.agent.exploit_evidence import synthesize_exploit_result


HOST = "192.0.2.11"
TOPIC = "smartcity/admin/credentials"


def frame(topic: str, payload: str) -> str:
    return json.dumps({
        "tst": "fixture", "topic": topic, "qos": 0, "retain": 0,
        "payload": payload,
    }, ensure_ascii=False)


def result(stdout: str, *, port: int = 1883, topic: str = "#") -> dict:
    return {
        "stdout": stdout, "return_code": 0,
        "execution_attestation": {
            "protocol": "TCP", "host": HOST, "port": port,
            "topic": topic, "output_format": "mosquitto-json-v1",
        },
    }


def test_parser_is_strict_but_preserves_unicode_line_separator_payloads():
    payload = "first\u2028second\nthird"
    assert parse_json_lines(frame(TOPIC, payload))[0]["payload"] == payload
    for stdout in (
        '{"topic":"x","topic":"y","payload":"p","tst":"t","qos":0,"retain":0}',
        '{"topic":"x","payload":',
        '[]',
        frame(TOPIC, 3),
    ):
        try:
            parse_json_lines(stdout)
        except MQTTFramingError:
            pass
        else:
            raise AssertionError("invalid framed output was accepted")


def test_mqtt_wildcards_are_case_sensitive_and_respect_sys_root_rule():
    assert mqtt_topic_matches("sensors/#", "sensors/temp/room")
    assert mqtt_topic_matches("sensors/+", "sensors/temp")
    assert mqtt_topic_matches("sensors/#", "sensors")
    assert not mqtt_topic_matches("Sensors/+", "sensors/temp")
    assert not mqtt_topic_matches("#", "$SYS/broker/version")
    assert not mqtt_topic_matches("+/#", "$SYS/broker/version")
    assert mqtt_topic_matches("$SYS/#", "$SYS/broker/version")


def test_real_mosquitto_payloadlen_metadata_does_not_hide_valid_messages():
    # Shape observed from the installed Mosquitto 2.0.21 client, not just
    # the smaller JSON example from the documentation.
    raw = '{"tst":"2026-09-12T17:22:48.153187+0200","topic":"smartcity/admin/credentials","qos":0,"retain":1,"payloadlen":22,"payload":"password=local-fixture"}\n'
    message, = parse_json_lines(raw)
    assert message["topic"] == TOPIC
    assert message["payload"] == "password=local-fixture"
    assert "payloadlen" not in message  # Metadata is retained in raw stdout only.


def test_selection_requires_both_subscription_and_claim_filters():
    stdout = "\n".join((
        frame("sensors/temp", "22"),
        frame(TOPIC, "password=fixture-secret"),
    ))
    selected = select_mqtt_messages(stdout, "#", "smartcity/+/credentials")
    assert [message["topic"] for message in selected] == [TOPIC]
    assert select_mqtt_messages(stdout, "sensors/#", TOPIC) == []


def test_trusted_messages_require_actual_attested_host_port_and_filter():
    args = {"broker": HOST, "port": "1883", "topic": "#"}
    good = result(frame(TOPIC, "password=fixture-secret") + "\n")
    assert trusted_mqtt_messages(good, args, HOST, "1883", TOPIC)
    assert not trusted_mqtt_messages(good, args, HOST, 1884, TOPIC)
    wrong = result(frame(TOPIC, "password=fixture-secret") + "\n")
    wrong["execution_attestation"]["host"] = "192.0.2.12"
    assert not trusted_mqtt_messages(wrong, args, HOST, 1883, TOPIC)


def test_wildcard_subscription_can_prove_only_the_claimed_framed_topic():
    finding = {
        "id": "V1", "type": "data_exposure", "service": "mqtt",
        "device_ip": HOST, "port": 1883, "endpoint": TOPIC,
    }
    record = {
        "tool": "mqtt_listen", "args": {"broker": HOST, "port": 1883, "topic": "#"},
        "result": result("\n".join((
            frame("sensors/temp", "password=wrong-topic-secret"),
            frame(TOPIC, "password=right-topic-secret"),
        )) + "\n"),
    }
    proof = synthesize_exploit_result(finding, [record])
    assert proof["status"] == "EXPLOITED"
    assert "right-topic-secret" in proof["evidence"]
    assert "wrong-topic-secret" not in proof["evidence"]


def test_declared_but_malformed_framing_never_falls_back_to_legacy():
    finding = {
        "id": "V1", "type": "no_auth", "service": "mqtt",
        "device_ip": HOST, "port": 1883, "endpoint": TOPIC,
    }
    record = {
        "tool": "mqtt_listen", "args": {"broker": HOST, "port": 1883, "topic": TOPIC},
        "result": result(f"{TOPIC} payload\n"),
    }
    assert synthesize_exploit_result(finding, [record])["status"] != "EXPLOITED"
