"""Independent proof checks for recorded MQTT-over-WebSocket captures."""
from __future__ import annotations

import base64
import binascii
import ipaddress
from typing import Any

from src.agent.evidence.mqtt import mqtt_topic_matches, normalize_mqtt_port


MQTT_WS_OUTPUT_FORMAT = "mqtt-ws-json-v1"


def _valid_ip(value: object) -> bool:
    if (
        not isinstance(value, str) or not value or value != value.strip()
        or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)
        or "%" in value or value.startswith("[") or value.endswith("]")
    ):
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def mqtt_ws_actual_request(args: dict) -> tuple[str, int, str, str] | None:
    if not isinstance(args, dict):
        return None
    if set(args) - {"ip", "port", "path", "topic", "count", "timeout"}:
        return None
    ip = args.get("ip")
    port = args.get("port") if type(args.get("port")) is int else None
    path = args.get("path")
    topic = args.get("topic")
    if (
        not _valid_ip(ip)
        or port is None or not 1 <= port <= 65535
        or not isinstance(path, str)
        or not path.startswith("/")
        or len(path) > 256
        or path.startswith("//")
        or any(ord(char) < 32 or ord(char) == 127 or char.isspace() for char in path)
        or any(marker in path for marker in ("\\", "://", "?", "#"))
        or any(code in path.casefold() for code in ("%2f", "%5c", "%3f", "%23", "%00"))
        or not isinstance(topic, str)
        or not topic
        or len(topic) > 256
        or any(ord(char) < 32 or ord(char) == 127 for char in topic)
    ):
        return None
    levels = topic.split("/")
    if any("#" in level and (level != "#" or index != len(levels) - 1)
           for index, level in enumerate(levels)):
        return None
    if any("+" in level and level != "+" for level in levels):
        return None
    for key, maximum in (("count", 100), ("timeout", 60)):
        value = args.get(key, 1 if key == "count" else 5)
        if type(value) is not int or not 1 <= value <= maximum:
            return None
    return ip, port, path, topic


def mqtt_ws_claim_path(vulnerability: dict) -> str | None:
    """Resolve the HTTP path claim without treating an MQTT topic as a path."""
    explicit_path = vulnerability.get("path")
    explicit_endpoint = vulnerability.get("endpoint")
    if explicit_path not in (None, "") and explicit_endpoint not in (None, ""):
        if explicit_path != explicit_endpoint:
            return None
    raw = explicit_path if explicit_path not in (None, "") else explicit_endpoint
    if raw in (None, ""):
        return "/"
    # A WebSocket endpoint is an HTTP path, not a URL. Rejecting URLs here
    # prevents a finding's prose host/port from being silently discarded.
    if not isinstance(raw, str) or not raw.startswith("/"):
        return None
    if (
        len(raw) > 256 or raw.startswith("//")
        or any(ord(char) < 32 or ord(char) == 127 or char.isspace() for char in raw)
        or any(marker in raw for marker in ("\\", "://", "?", "#"))
        or any(code in raw.casefold() for code in ("%2f", "%5c", "%3f", "%23", "%00"))
    ):
        return None
    return raw


def mqtt_ws_claim_topic(vulnerability: dict) -> str | None:
    """Resolve the MQTT filter claim from an explicit topic field only."""
    values = [vulnerability.get(key) for key in ("mqtt_topic", "topic", "topic_filter")
              if vulnerability.get(key) not in (None, "")]
    if any(not isinstance(value, str) for value in values) or len(set(values)) > 1:
        return None
    for key in ("mqtt_topic", "topic", "topic_filter"):
        value = vulnerability.get(key)
        if isinstance(value, str) and value:
            levels = value.split("/")
            if (
                len(value) > 256
                or any(ord(char) < 32 or ord(char) == 127 for char in value)
                or any("#" in level and (level != "#" or index != len(levels) - 1)
                       for index, level in enumerate(levels))
                or any("+" in level and level != "+" for level in levels)
            ):
                return None
            return value
    return "#"


def _attestation_matches(
    result: dict, args: dict, target_ip: object, target_port: object,
    target_path: object, target_topic: object,
) -> bool:
    actual = mqtt_ws_actual_request(args)
    if actual is None or not isinstance(result, dict):
        return False
    ip, port, path, topic = actual
    claimed_port = normalize_mqtt_port(target_port)
    attestation = result.get("execution_attestation")
    if not isinstance(attestation, dict) or claimed_port is None:
        return False
    if not _valid_ip(target_ip) or ip != target_ip or port != claimed_port:
        return False
    if not isinstance(target_path, str) or target_path != path:
        return False
    if not isinstance(target_topic, str) or target_topic != topic:
        return False
    return (
        attestation.get("output_format") == MQTT_WS_OUTPUT_FORMAT
        and attestation.get("protocol") == "MQTTv311"
        and attestation.get("transport") == "websockets"
        and attestation.get("ip") == ip
        and attestation.get("host") == ip
        and attestation.get("port") == port
        and attestation.get("path") == path
        and attestation.get("topic") == topic
        and attestation.get("no_auth") is True
        and attestation.get("auth") == "no_auth"
        and attestation.get("clean_session") is True
        and attestation.get("reconnect_on_failure") is False
    )


def _complete_message(message: object) -> dict[str, Any] | None:
    if not isinstance(message, dict):
        return None
    topic = message.get("topic")
    payload = message.get("payload")
    if (
        not isinstance(topic, str) or not topic or len(topic) > 256
        or "+" in topic or "#" in topic
        or not isinstance(payload, str)
        or type(message.get("raw_payload_complete")) is not bool
        or message.get("raw_payload_complete") is not True
        or type(message.get("raw_topic_complete")) is not bool
        or message.get("raw_topic_complete") is not True
        or type(message.get("payload_length")) is not int
        or message.get("payload_length") < 0
        or message.get("payload_length") > 16 * 1024
        or type(message.get("qos")) is not int
        or message.get("qos") not in {0, 1, 2}
        or type(message.get("retain")) is not bool
        or not isinstance(message.get("captured_at"), str)
    ):
        return None
    try:
        if len(topic.encode("utf-8")) > 256:
            return None
    except UnicodeError:
        return None
    payload_b64 = message.get("payload_b64")
    if not isinstance(payload_b64, str):
        return None
    try:
        decoded = base64.b64decode(payload_b64, validate=True)
    except (ValueError, binascii.Error):
        return None
    if len(decoded) != message["payload_length"]:
        return None
    try:
        if decoded.decode("utf-8", errors="replace") != payload:
            return None
    except UnicodeError:
        return None
    return message


def _strict_zero_list(value: object) -> bool:
    """Accept exactly one integer MQTT success/granted-QoS-0 code."""
    return isinstance(value, list) and len(value) == 1 and type(value[0]) is int and value[0] == 0


def trusted_mqtt_ws_messages(
    result: dict, args: dict, target_ip: object, target_port: object,
    target_path: object, claim_topic: str,
) -> list[dict[str, Any]]:
    """Return only complete, freshly recorded messages from a bound exchange."""
    actual = mqtt_ws_actual_request(args)
    if (
        actual is None or not isinstance(claim_topic, str)
        or actual[3] != claim_topic
        or not _attestation_matches(result, args, target_ip, target_port, target_path, claim_topic)
    ):
        return []
    expected_status = result.get("status")
    if (
        result.get("ok") is not True
        or result.get("success") is not True
        or result.get("error") not in (None, "")
        or result.get("cancelled") is True
        or result.get("output_truncated") is True
        or expected_status not in {"success", "timeout"}
        or result.get("partial_timeout") is not (expected_status == "timeout")
        or (expected_status == "success" and (
            result.get("return_code") != 0
            or result.get("timed_out") is not False
            or result.get("partial_timeout") is not False
        ))
        or (expected_status == "timeout" and (
            result.get("return_code") != 27
            or result.get("timed_out") is not True
            or result.get("partial_timeout") is not True
        ))
    ):
        return []
    connack = result.get("connack")
    suback = result.get("suback")
    if (
        not isinstance(connack, dict)
        or connack.get("received") is not True
        or connack.get("accepted") is not True
        or not isinstance(suback, dict)
        or suback.get("received") is not True
        or suback.get("accepted") is not True
        or type(connack.get("reason_code")) is not int
        or connack.get("reason_code") != 0
        or not _strict_zero_list(suback.get("reason_codes"))
        or not _strict_zero_list(suback.get("granted_qos"))
        or not _strict_zero_list(suback.get("requested_qos"))
        or suback.get("mid_matches_request") is not True
        or type(suback.get("mid")) is not int
        or not 1 <= suback.get("mid") <= 65535
        or type(result.get("subscribe_mid")) is not int
        or not 1 <= result.get("subscribe_mid") <= 65535
        or suback.get("mid") != result.get("subscribe_mid")
    ):
        return []
    messages = result.get("messages")
    requested_count = args.get("count", 1)
    if (
        not isinstance(messages, list)
        or type(result.get("received_count")) is not int
        or result.get("received_count") != len(messages)
        or type(result.get("requested_count")) is not int
        or result.get("requested_count") != requested_count
        or len(messages) == 0
        or len(messages) > requested_count
        or (expected_status == "success" and len(messages) != requested_count)
        or (expected_status == "timeout" and len(messages) >= requested_count)
    ):
        return []
    actual_topic = str(args.get("topic"))
    accepted: list[dict[str, Any]] = []
    total_bytes = 0
    for message in messages:
        valid = _complete_message(message)
        if valid is None:
            return []
        topic = valid["topic"]
        total_bytes += len(topic.encode("utf-8")) + valid["payload_length"]
        if total_bytes > 64 * 1024:
            return []
        if not mqtt_topic_matches(actual_topic, topic) or not mqtt_topic_matches(claim_topic, topic):
            continue
        accepted.append({
            "topic": topic,
            "payload": valid["payload"],
            "payload_b64": valid["payload_b64"],
            "qos": valid["qos"],
            "retain": valid["retain"],
            "captured_at": valid["captured_at"],
        })
    return accepted


def mqtt_ws_exchange_proven(
    result: dict, args: dict, target_ip: object, target_port: object,
    target_path: object, claim_topic: str,
) -> bool:
    return bool(trusted_mqtt_ws_messages(
        result, args, target_ip, target_port, target_path, claim_topic,
    ))
