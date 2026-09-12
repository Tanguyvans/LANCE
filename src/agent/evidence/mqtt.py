"""Strict MQTT topic attribution for recorded mosquitto_sub output.

The subprocess producer owns the ``-F %j`` invocation and keeps stdout as raw
JSONL.  This module only interprets that output after the execution
attestation has bound it to the actual MQTT/TCP request.
"""
from __future__ import annotations

import json
from typing import Any


MOSQUITTO_JSON_OUTPUT_FORMAT = "mosquitto-json-v1"
DEFAULT_MQTT_PORT = 1883
DEFAULT_MQTT_TOPIC = "#"


class MQTTFramingError(ValueError):
    """Raised when stdout is not a complete, strictly framed MQTT stream."""


class _DuplicateKeyError(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _is_json_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def normalize_mqtt_port(value: object) -> int | None:
    """Normalize an MQTT port accepted by the producer contract."""
    if _is_json_int(value):
        port = value
    elif type(value) is str and value.isascii() and value.isdigit():
        try:
            port = int(value)
        except ValueError:
            return None
    else:
        return None
    return port if 1 <= port <= 65535 else None


def _validate_message(message: object, line_number: int) -> dict[str, Any]:
    if not isinstance(message, dict):
        raise MQTTFramingError(f"MQTT JSON line {line_number} is not an object")
    required = {"tst", "topic", "qos", "retain", "payload"}
    # Mosquitto 2.0 also emits payloadlen (omitted in older documentation).
    # Additional client metadata is not evidence and must not invalidate the
    # required, independently typed topic/payload fields.
    if not required.issubset(message):
        raise MQTTFramingError(f"MQTT JSON line {line_number} has invalid fields")
    if not isinstance(message["tst"], str):
        raise MQTTFramingError(f"MQTT JSON line {line_number} has an invalid tst")
    if not isinstance(message["topic"], str) or not message["topic"]:
        raise MQTTFramingError(f"MQTT JSON line {line_number} has an invalid topic")
    if not isinstance(message["payload"], str):
        raise MQTTFramingError(f"MQTT JSON line {line_number} has an invalid payload")
    if not _is_json_int(message["qos"]) or not 0 <= message["qos"] <= 2:
        raise MQTTFramingError(f"MQTT JSON line {line_number} has an invalid qos")
    if not _is_json_int(message["retain"]) or message["retain"] not in (0, 1):
        raise MQTTFramingError(f"MQTT JSON line {line_number} has an invalid retain")
    # A published topic is concrete.  Wildcards belong only to subscriptions.
    if "+" in message["topic"] or "#" in message["topic"]:
        raise MQTTFramingError(f"MQTT JSON line {line_number} has a wildcard topic")
    return {key: message[key] for key in ("tst", "topic", "qos", "retain", "payload")}


def parse_json_lines(stdout: str) -> list[dict[str, Any]]:
    """Parse a complete mosquitto ``%j`` JSONL stream, or reject it.

    Blank stdout and trailing blank lines represent no captured messages and
    return an empty list.  Any malformed, truncated, non-object, duplicate-key
    or wrongly typed line rejects the complete stream; callers must not salvage
    neighbouring lines as evidence.
    """
    if not isinstance(stdout, str):
        raise MQTTFramingError("MQTT stdout is not text")
    messages: list[dict[str, Any]] = []
    # JSON strings may contain Unicode line-separator characters (for example
    # U+2028) as payload data.  JSONL framing is the literal LF delimiter only.
    for line_number, line in enumerate(stdout.split("\n"), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(
                line,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=lambda constant: (_ for _ in ()).throw(
                    ValueError(f"invalid JSON constant: {constant}")
                ),
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise MQTTFramingError(
                f"invalid MQTT JSON line {line_number}: {exc}"
            ) from exc
        messages.append(_validate_message(value, line_number))
    return messages


def mqtt_topic_matches(topic_filter: str, topic_name: str) -> bool:
    """Apply MQTT ``#``/``+`` matching with MQTT's ``$SYS`` rule.

    Matching is case-sensitive.  Invalid filters and wildcard-containing topic
    names fail closed.
    """
    if not isinstance(topic_filter, str) or not isinstance(topic_name, str):
        return False
    if not topic_filter or not topic_name:
        return False
    if "+" in topic_name or "#" in topic_name:
        return False
    filter_levels = topic_filter.split("/")
    topic_levels = topic_name.split("/")
    for index, level in enumerate(filter_levels):
        if level == "#":
            if index != len(filter_levels) - 1:
                return False
            if topic_levels and topic_levels[0].startswith("$") and index == 0:
                return False
            return len(topic_levels) >= index
        if level not in {"+"} and ("+" in level or "#" in level):
            return False
        if index >= len(topic_levels):
            return False
        if index == 0 and topic_levels[0].startswith("$") and level == "+":
            return False
        if level != "+" and level != topic_levels[index]:
            return False
    return len(topic_levels) == len(filter_levels)


def select_mqtt_messages(
    stdout: str, subscribed_filter: str, claim_filter: str,
) -> list[dict[str, Any]]:
    """Return framed messages covered by both subscription and claim filters."""
    if not isinstance(claim_filter, str) or not claim_filter:
        return []
    try:
        messages = parse_json_lines(stdout)
    except MQTTFramingError:
        return []
    return [
        message for message in messages
        if mqtt_topic_matches(subscribed_filter, message["topic"])
        and mqtt_topic_matches(claim_filter, message["topic"])
    ]


def legacy_exact_topic_payloads(stdout: str, topic: str) -> list[str]:
    """Extract payloads from the old ``-v`` form for one exact topic only.

    This compatibility path deliberately does not parse or widen wildcard
    subscriptions.  It is only usable when the caller has already established
    that the requested topic equals the claimed topic.
    """
    if not isinstance(stdout, str) or not isinstance(topic, str) or not topic:
        return []
    payloads: list[str] = []
    for line in stdout.split("\n"):
        if line == topic:
            payloads.append("")
        elif line.startswith(topic + " "):
            payloads.append(line[len(topic) + 1:])
    return payloads


def legacy_verbose_messages(stdout: str, subscribed_filter: str) -> list[dict[str, str]]:
    """Read old ``topic payload`` lines limited to the requested filter."""
    if not isinstance(stdout, str) or not isinstance(subscribed_filter, str):
        return []
    messages: list[dict[str, str]] = []
    for line in stdout.split("\n"):
        topic, separator, payload = line.partition(" ")
        if separator and mqtt_topic_matches(subscribed_filter, topic):
            messages.append({"topic": topic, "payload": payload})
    return messages


def mqtt_framing_declared(result: dict) -> bool:
    """Whether a result declares any output format and forbids legacy fallback."""
    attestation = result.get("execution_attestation") if isinstance(result, dict) else None
    return isinstance(attestation, dict) and "output_format" in attestation


def primary_mqtt_claim(vulnerability: dict) -> str:
    """Use endpoint first, otherwise the first non-empty secondary endpoint."""
    endpoint = vulnerability.get("endpoint")
    if isinstance(endpoint, str) and endpoint:
        return endpoint
    endpoints = vulnerability.get("endpoints") or []
    values = endpoints if isinstance(endpoints, (list, tuple, set)) else [endpoints]
    return next((value for value in values if isinstance(value, str) and value), "")


def mqtt_actual_request(args: dict) -> tuple[str, int, str] | None:
    """Resolve the effective producer request, including MQTT defaults."""
    if not isinstance(args, dict) or not isinstance(args.get("broker"), str):
        return None
    host = args["broker"]
    if not host:
        return None
    topic = args.get("topic", DEFAULT_MQTT_TOPIC)
    port = args.get("port", DEFAULT_MQTT_PORT)
    if not isinstance(topic, str) or not topic:
        return None
    port = normalize_mqtt_port(port)
    if port is None:
        return None
    return host, port, topic


def trusted_mqtt_messages(
    result: dict, args: dict, target_host: object, target_port: object,
    claim_filter: str,
) -> list[dict[str, Any]]:
    """Select messages only from a correctly attested ``mosquitto -F %j`` run."""
    actual = mqtt_actual_request(args)
    if actual is None or not isinstance(result, dict):
        return []
    host, port, subscribed_filter = actual
    if target_port in (None, ""):
        claimed_port = port
    else:
        claimed_port = normalize_mqtt_port(target_port)
    if claimed_port is None or not isinstance(target_host, str):
        return []
    attestation = result.get("execution_attestation")
    if not isinstance(attestation, dict):
        return []
    if (
        attestation.get("output_format") != MOSQUITTO_JSON_OUTPUT_FORMAT
        or attestation.get("protocol") != "TCP"
        or attestation.get("host") != host
        or not _is_json_int(attestation.get("port"))
        or attestation.get("port") != port
        or attestation.get("topic") != subscribed_filter
        or host != target_host
        or port != claimed_port
    ):
        return []
    return select_mqtt_messages(str(result.get("stdout", "")), subscribed_filter, claim_filter)
