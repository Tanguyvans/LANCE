"""Narrow, observation-backed MQTT duplicate grouping for Phase 3 output."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from src.agent.evidence.mqtt import (
    MQTTFramingError,
    mqtt_actual_request,
    mqtt_topic_matches,
    normalize_mqtt_port,
    parse_json_lines,
)


_SENSITIVE_PAYLOAD_RE = re.compile(
    r"(?i)(password|passwd|pass|secret|api[_-]?key|token|credential)"
)
_AUTH_FIELDS = (
    "username", "password", "user", "auth_identity", "auth_user",
    "client_id", "client_identity", "principal", "credential_identity",
    "auth", "authentication", "auth_mode",
)
_CLAIM_FIELDS = (
    "condition", "conditions", "parameter", "parameters", "vector", "vectors",
    "attack_vector", "attack_vectors", "claim", "claims", "claim_id", "claim_ids",
    "cve", "cve_id", "cve_ids", "cves",
)


def _result_object(value: object) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return None
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _archived_mqtt_entries(run_dir: Path) -> list[tuple[str, int, dict]]:
    entries: list[tuple[str, int, dict]] = []
    scans_dir = run_dir / "03_scans"
    scan_paths = sorted(scans_dir.glob("*.json")) if scans_dir.is_dir() else []
    for path in scan_paths:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            continue
        values = (
            [item for group in document.values() if isinstance(group, list) for item in group]
            if isinstance(document, dict)
            else document if isinstance(document, list) else []
        )
        entries.extend(
            (path.name, index, item)
            for index, item in enumerate(values)
            if isinstance(item, dict)
        )

    ledger = run_dir / "tool_calls.jsonl"
    if ledger.is_file():
        try:
            lines = ledger.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            lines = []
        for index, line in enumerate(lines):
            try:
                item = json.loads(line)
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if not isinstance(item, dict) or item.get("tool") != "mqtt_listen":
                continue
            phase = item.get("phase")
            if phase is not None and phase not in {2, 3}:
                continue
            entries.append((ledger.name, index, item))
    return entries


def load_authoritative_mqtt_observations(run_dir: Path) -> list[dict[str, Any]]:
    """Load complete anonymous Phase 3 MQTT observations only.

    Candidate evidence is never parsed.  The actual result must bind host,
    port, topic and TCP transport to an attested, strictly framed JSONL stream.
    """
    observations: list[dict[str, Any]] = []
    seen: set[tuple] = set()
    for source_file, source_index, entry in _archived_mqtt_entries(run_dir):
        if entry.get("tool") != "mqtt_listen":
            continue
        if source_file != "tool_calls.jsonl" and entry.get("authoritative") is False:
            continue
        args = entry.get("kwargs") if isinstance(entry.get("kwargs"), dict) else entry.get("args")
        if not isinstance(args, dict):
            continue
        request = mqtt_actual_request(args)
        if request is None:
            continue
        host, requested_port, requested_topic = request
        result = _result_object(entry.get("result"))
        attestation = result.get("execution_attestation") if result else None
        if not isinstance(attestation, dict):
            continue
        actual_port = normalize_mqtt_port(attestation.get("port"))
        if (
            str(attestation.get("host") or "") != host
            or actual_port != requested_port
            or str(attestation.get("protocol") or "").casefold() != "tcp"
            or attestation.get("topic") != requested_topic
            or attestation.get("output_format") != "mosquitto-json-v1"
            or args.get("username") or args.get("password")
        ):
            continue
        if (
            result.get("success") is False
            or result.get("error")
            or result.get("cancelled") is True
            or result.get("canceled") is True
            or result.get("truncated") is True
            or result.get("is_truncated") is True
            or result.get("output_truncated") is True
            or str(result.get("status") or "").casefold() in {"error", "failed", "cancelled", "canceled"}
        ):
            continue
        return_code = result.get("return_code")
        if isinstance(return_code, bool):
            continue
        if isinstance(return_code, int):
            pass
        elif type(return_code) is str and return_code.isascii() and return_code.isdigit():
            try:
                return_code = int(return_code)
            except ValueError:
                continue
        else:
            continue
        stdout = result.get("stdout")
        if return_code not in {0, 27} or not isinstance(stdout, str) or not stdout.strip():
            continue
        try:
            messages = parse_json_lines(stdout)
        except (MQTTFramingError, TypeError, ValueError):
            continue
        if not messages:
            continue
        # Match the existing MQTT evidence boundary: unrelated messages in a
        # broad capture are ignored, but at least one message must be covered
        # by the requested subscription.  Sensitive-resource identity is
        # derived from the selected messages only.
        messages = [
            message for message in messages
            if mqtt_topic_matches(requested_topic, message["topic"])
        ]
        if not messages:
            continue
        sensitive = [
            message for message in messages
            if _SENSITIVE_PAYLOAD_RE.search(message["payload"])
        ]
        key = (
            host, requested_port, "tcp", requested_topic,
            tuple(sorted((message["topic"], message["payload"]) for message in sensitive)),
        )
        if key in seen:
            continue
        seen.add(key)
        observations.append({
            "key": key,
            "host": host,
            "port": requested_port,
            "protocol": "tcp",
            "requested_topic": requested_topic,
            "messages": messages,
            "sensitive_messages": sensitive,
            "source_file": source_file,
            "source_index": source_index,
            "evidence_ref": str(entry.get("evidence_ref") or "").strip(),
        })
    return observations


def _exact_values(finding: dict, field: str) -> tuple[str, ...]:
    if field not in finding or finding.get(field) is None:
        return ()
    raw = finding.get(field)
    raw_values = raw if isinstance(raw, (list, tuple, set)) else [raw]
    return tuple(sorted({str(value) for value in raw_values if value is not None and str(value) != ""}))


def _metadata_values(finding: dict, field: str) -> tuple[str, ...]:
    if field not in finding or finding.get(field) is None:
        return ()
    raw = finding.get(field)
    raw_values = raw if isinstance(raw, (list, tuple, set)) else [raw]
    return tuple(sorted({
        re.sub(r"\s+", " ", str(value).strip().casefold())
        for value in raw_values if value is not None and str(value).strip()
    }))


def _topics(finding: dict) -> tuple[str, ...]:
    values: list[str] = []
    for field in ("endpoint", "endpoints", "topic", "topics", "mqtt_topic", "topic_filter"):
        values.extend(_exact_values(finding, field))
    return tuple(sorted(set(values)))


def _metadata_compatible(left: dict, right: dict) -> bool:
    for field in ("product", "version"):
        first, second = _metadata_values(left, field), _metadata_values(right, field)
        if first and second and first != second:
            return False
    for field in _AUTH_FIELDS + _CLAIM_FIELDS:
        if _exact_values(left, field) != _exact_values(right, field):
            return False
    return True


def _operation(finding: dict, *, scanner: bool) -> str:
    structured = " ".join(
        str(finding.get(field) or "")
        for field in ("operation", "action", "vector", "claim", "parameter")
    )
    narrative = " ".join(
        str(finding.get(field) or "") for field in ("details", "evidence")
    )
    text = f"{structured} {narrative}".casefold()
    subscribe = bool(re.search(r"\b(?:subscribe|subscription|subscribing|mqtt_listen|listen)\b", text))
    publish = bool(re.search(r"\b(?:publish|publishing|publisher|mosquitto_pub|write|writing)\b", text))
    if subscribe and publish:
        return "ambiguous"
    if publish:
        return "publish"
    if subscribe:
        return "subscribe"
    return "subscribe" if scanner else "ambiguous"


def _candidate_keys(finding: dict, observations: list[dict[str, Any]]) -> set[tuple]:
    if str(finding.get("service") or "").casefold() != "mqtt":
        return set()
    target = str(finding.get("device_ip") or "").strip()
    port = normalize_mqtt_port(finding.get("port"))
    if not target or port is None or str(finding.get("protocol") or "").casefold() != "tcp":
        return set()
    vuln_type = str(finding.get("type") or "").casefold()
    if vuln_type not in {"no_auth", "data_exposure"}:
        return set()
    topics = _topics(finding)
    if len(topics) > 1:
        return set()
    scanner = str(finding.get("_source_kind") or "").startswith("scanner")
    if vuln_type == "no_auth" and _operation(finding, scanner=scanner) != "subscribe":
        return set()
    if vuln_type == "no_auth" and not topics:
        # Scanner excerpts record this exact invocation prefix even when the
        # message body is clipped. It only narrows the archived subscription
        # lookup; the excerpt itself is never accepted as execution evidence.
        hints = set(re.findall(
            r"\bmqtt_listen\(topic=([^(),\r\n]+)\)",
            str(finding.get("evidence") or ""),
        ))
        if len(hints) > 1:
            return set()
        if hints:
            topics = tuple(hints)

    matched: set[tuple] = set()
    for observation in observations:
        if (observation["host"], observation["port"], observation["protocol"]) != (target, port, "tcp"):
            continue
        if vuln_type == "no_auth":
            if topics and topics[0] != observation["requested_topic"]:
                continue
            matched.add(("no_auth", target, port, "tcp", observation["requested_topic"]))
            continue
        sensitive = observation["sensitive_messages"]
        if topics:
            sensitive = [message for message in sensitive if message["topic"] == topics[0]]
        elif len({(message["topic"], message["payload"]) for message in sensitive}) != 1:
            continue
        for message in {(item["topic"], item["payload"]) for item in sensitive}:
            matched.add(("data_exposure", target, port, "tcp", *message))
    return matched


def _stable_key(finding: dict) -> str:
    return repr(sorted(finding.items(), key=lambda item: str(item[0])))


def group_mqtt_producer_findings(
    findings: list[dict], *, run_dir: Path,
) -> list[tuple[list[dict], bool]]:
    """Combine only one unambiguous model/scanner pair per observation."""
    from src.agent.finding_identity import finding_identity_key, group_equivalent_findings

    observations = load_authoritative_mqtt_observations(run_dir)
    matched = {id(finding): _candidate_keys(finding, observations) for finding in findings}
    components: list[dict[str, Any]] = [
        {"findings": list(group), "producer": False}
        for group in group_equivalent_findings(findings)
    ]

    def source_is(group: dict[str, Any], kind: str) -> bool:
        return any(str(item.get("_source_kind") or "") == kind for item in group["findings"])

    def scanner_is(group: dict[str, Any]) -> bool:
        return any(str(item.get("_source_kind") or "").startswith("scanner") for item in group["findings"])

    def common_keys(group: dict[str, Any]) -> set[tuple]:
        values = [matched[id(item)] for item in group["findings"]]
        return set.intersection(*values) if values else set()

    def compatible(left: dict[str, Any], right: dict[str, Any]) -> bool:
        if not ((scanner_is(left) and source_is(right, "model")) or (source_is(left, "model") and scanner_is(right))):
            return False
        combined = left["findings"] + right["findings"]
        if not common_keys({"findings": combined}):
            return False
        for index, first in enumerate(combined):
            for second in combined[index + 1:]:
                if not _metadata_compatible(first, second):
                    return False
                if str(first.get("type") or "").casefold() != str(second.get("type") or "").casefold():
                    return False
                first_topics, second_topics = _topics(first), _topics(second)
                if first_topics and second_topics and first_topics != second_topics:
                    return False
        return True

    # Do not greedily attach an incomplete candidate to whichever complete
    # anchor happens to be visited first.  A producer key must have exactly
    # one model component and one scanner component.
    key_to_components: dict[tuple, list[int]] = {}
    for index, component in enumerate(components):
        keys = common_keys(component)
        if len(keys) == 1:
            key_to_components.setdefault(next(iter(keys)), []).append(index)
    merged: set[int] = set()
    for indexes in key_to_components.values():
        if len(indexes) != 2:
            continue
        left, right = components[indexes[0]], components[indexes[1]]
        if not compatible(left, right):
            continue
        left["findings"] = sorted(left["findings"] + right["findings"], key=_stable_key)
        left["producer"] = True
        merged.add(indexes[1])

    result = [component for index, component in enumerate(components) if index not in merged]
    result.sort(key=lambda component: (
        repr(finding_identity_key(component["findings"][0])[:6] + finding_identity_key(component["findings"][0])[8:]),
        _stable_key(component["findings"][0]),
    ))
    return [(component["findings"], bool(component["producer"])) for component in result]
