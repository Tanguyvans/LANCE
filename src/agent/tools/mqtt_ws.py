"""Read-only MQTT-over-WebSocket verification using paho-mqtt.

This is deliberately a separate tool from ``mqtt_listen``.  The latter is
MQTT/TCP and must never be used to prove a WebSocket endpoint.  This handler
uses paho's MQTT implementation for the CONNECT, SUBSCRIBE, and PUBLISH
exchange; it does not hand-roll either protocol.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import socket
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from src.agent.tools.runtime import get_tool_stop_event


MQTT_WS_OUTPUT_FORMAT = "mqtt-ws-json-v1"
MQTT_WS_TRANSPORT = "websockets"
MAX_PATH_LENGTH = 256
MAX_TOPIC_LENGTH = 256
MAX_COUNT = 100
MAX_TIMEOUT_SECONDS = 60
MAX_PAYLOAD_BYTES = 16 * 1024
MAX_TOTAL_PAYLOAD_BYTES = 64 * 1024
WEBSOCKET_KEEPALIVE_SECONDS = 1


def _error(error_kind: str, message: str) -> str:
    return json.dumps({
        "ok": False,
        "success": False,
        "status": "error",
        "error_kind": error_kind,
        "error": message,
        "messages": [],
    }, ensure_ascii=False)


def _valid_ip(value: object) -> str | None:
    if type(value) is not str or not value or value != value.strip():
        return None
    if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    if "%" in value or value.startswith("[") or value.endswith("]"):
        return None
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return None
    return value


def _valid_path(value: object) -> str | None:
    """Accept one unambiguous HTTP path, never a URL or header fragment."""
    if type(value) is not str or not value or len(value) > MAX_PATH_LENGTH:
        return None
    if not value.startswith("/") or value.startswith("//"):
        return None
    if any(ord(char) < 32 or ord(char) == 127 or char.isspace() for char in value):
        return None
    if any(marker in value for marker in ("\\", "://", "?", "#")):
        return None
    # Encoded separators/query delimiters make the actual endpoint ambiguous.
    lowered = value.casefold()
    if any(code in lowered for code in ("%2f", "%5c", "%3f", "%23", "%00")):
        return None
    return value


def _valid_topic(value: object) -> str | None:
    if type(value) is not str or not value or len(value) > MAX_TOPIC_LENGTH:
        return None
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    levels = value.split("/")
    for index, level in enumerate(levels):
        if "#" in level and (level != "#" or index != len(levels) - 1):
            return None
        if "+" in level and level != "+":
            return None
    return value


def _valid_port(value: object) -> int | None:
    if type(value) is not int or not 1 <= value <= 65535:
        return None
    return value


def _valid_limit(value: object, *, maximum: int) -> int | None:
    if type(value) is not int or not 1 <= value <= maximum:
        return None
    return value


def _reason_value(reason: object) -> int | str:
    value = getattr(reason, "value", reason)
    if type(value) is int:
        return value
    return str(value)


def _reason_ok(reason: object) -> bool:
    value = _reason_value(reason)
    return value == 0 or str(value).casefold() in {"success", "granted qos 0"}


def _message_record(message: object, total_payload_bytes: int) -> tuple[dict[str, Any], int, bool]:
    topic = str(getattr(message, "topic", ""))
    payload = getattr(message, "payload", b"")
    if isinstance(payload, str):
        payload_bytes = payload.encode("utf-8", errors="replace")
    else:
        try:
            payload_bytes = bytes(payload)
        except (TypeError, ValueError):
            payload_bytes = b""
    topic_bytes = topic.encode("utf-8", errors="replace")
    kept_topic_bytes = topic_bytes[:MAX_TOPIC_LENGTH]
    remaining = max(0, MAX_TOTAL_PAYLOAD_BYTES - total_payload_bytes - len(kept_topic_bytes))
    keep = min(len(payload_bytes), MAX_PAYLOAD_BYTES, remaining)
    complete = keep == len(payload_bytes) and len(topic_bytes) <= MAX_TOPIC_LENGTH
    kept = payload_bytes[:keep]
    record: dict[str, Any] = {
        "topic": kept_topic_bytes.decode("utf-8", errors="replace"),
        "payload": kept.decode("utf-8", errors="replace"),
        "payload_b64": base64.b64encode(kept).decode("ascii"),
        "payload_length": len(payload_bytes),
        "raw_payload_complete": complete,
        "raw_topic_complete": len(topic_bytes) <= MAX_TOPIC_LENGTH,
        "qos": int(getattr(message, "qos", 0) or 0),
        "retain": bool(getattr(message, "retain", False)),
        "captured_at": datetime.now(timezone.utc).isoformat(),
    }
    return record, total_payload_bytes + len(kept_topic_bytes) + keep, not complete


class _DeadlineSocket:
    """Enforce one absolute deadline across a paho WebSocket handshake."""

    def __init__(self, sock: socket.socket, deadline: float, stop_event: Any):
        self._sock = sock
        self._deadline = deadline
        self._stop_event = stop_event

    def _remaining(self) -> float:
        if self._stop_event is not None and self._stop_event.is_set():
            raise OSError("MQTT WebSocket connection cancelled")
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("MQTT WebSocket deadline exceeded")
        return remaining

    def settimeout(self, _timeout: float | None) -> None:
        self._sock.settimeout(min(0.2, self._remaining()))

    def recv(self, length: int, *args: Any) -> bytes:
        while True:
            self._sock.settimeout(min(0.2, self._remaining()))
            try:
                return self._sock.recv(length, *args)
            except socket.timeout:
                self._remaining()

    def send(self, data: bytes, *args: Any) -> int:
        self._sock.settimeout(min(0.2, self._remaining()))
        return self._sock.send(data, *args)

    def close(self) -> None:
        self._sock.close()

    def fileno(self) -> int:
        return self._sock.fileno()

    def setblocking(self, flag: bool) -> None:
        self._sock.setblocking(flag)

    def pending(self) -> int:
        return self._sock.pending() if hasattr(self._sock, "pending") else 0


def mqtt_ws_listen(
    ip: str,
    port: int,
    path: str,
    topic: str,
    count: int = 1,
    timeout: int = 5,
    **kwargs: Any,
) -> str:
    """Perform one anonymous, bounded MQTT v3.1.1 WebSocket subscription."""
    if kwargs:
        return _error("invalid_tool_arguments", "Unknown MQTT WebSocket arguments")
    ip_value = _valid_ip(ip)
    port_value = _valid_port(port)
    path_value = _valid_path(path)
    topic_value = _valid_topic(topic)
    count_value = _valid_limit(count, maximum=MAX_COUNT)
    timeout_value = _valid_limit(timeout, maximum=MAX_TIMEOUT_SECONDS)
    if not all((ip_value, port_value, path_value, topic_value, count_value, timeout_value)):
        return _error(
            "invalid_tool_arguments",
            "Expected an IP literal, port 1-65535, one WebSocket path, one MQTT topic filter, "
            "count 1-100, and timeout 1-60 seconds",
        )

    stop_event = get_tool_stop_event()
    if stop_event is not None and stop_event.is_set():
        return _error("cancelled", "MQTT WebSocket verification cancelled before connection")

    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        return _error("dependency_unavailable", "paho-mqtt 2.x is required for MQTT WebSocket verification")

    state: dict[str, Any] = {
        "connack": {"received": False, "reason_code": None},
        "suback": {"received": False, "reason_codes": []},
        "messages": [],
        "total_payload_bytes": 0,
        "output_truncated": False,
        "connection_error": None,
        "subscribe_mid": None,
    }

    deadline = time.monotonic() + timeout_value

    # paho consults mqtt_proxy/PySocks defaults.  This instance-level override
    # prevents environment or process-global proxy state from rerouting the
    # explicitly selected IP; no environment variables are changed.
    class _DirectWebsocketClient(mqtt.Client):
        def _get_proxy(self):  # type: ignore[no-untyped-def]
            return None

        def _create_socket_connection(self):  # type: ignore[no-untyped-def]
            # Do not use paho's proxy/environment path. Short connect slices
            # make cancellation observable before the absolute deadline.
            while True:
                if stop_event is not None and stop_event.is_set():
                    raise OSError("MQTT WebSocket connection cancelled")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("MQTT WebSocket deadline exceeded")
                try:
                    raw = socket.create_connection(
                        (self._host, self._port), timeout=min(0.2, remaining),
                    )
                    return _DeadlineSocket(raw, deadline, stop_event)
                except socket.timeout:
                    continue

    client = None

    def on_connect(_client, _userdata, _flags, reason_code, _properties):
        state["connack"] = {
            "received": True,
            "reason_code": _reason_value(reason_code),
            "accepted": _reason_ok(reason_code),
        }
        if _reason_ok(reason_code):
            try:
                response = _client.subscribe(topic_value, qos=0)
                state["subscribe_mid"] = response[1] if isinstance(response, tuple) and len(response) > 1 else None
            except Exception as exc:  # pragma: no cover - paho-specific failure
                state["connection_error"] = f"subscribe_error:{type(exc).__name__}"

    def on_subscribe(_client, _userdata, _mid, reason_codes, _properties):
        values = list(reason_codes or [])
        state["suback"] = {
            "received": True,
            "mid": _mid,
            "reason_codes": [_reason_value(value) for value in values],
            "requested_qos": [0],
            "granted_qos": [_reason_value(value) for value in values],
            "mid_matches_request": (
                state["subscribe_mid"] is not None
                and _mid == state["subscribe_mid"]
            ),
            "accepted": bool(values) and all(_reason_ok(value) for value in values),
        }

    def on_message(_client, _userdata, message):
        if len(state["messages"]) >= count_value or state["output_truncated"]:
            return
        record, total, truncated = _message_record(message, state["total_payload_bytes"])
        state["total_payload_bytes"] = total
        state["messages"].append(record)
        state["output_truncated"] = state["output_truncated"] or truncated

    try:
        client = _DirectWebsocketClient(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id=f"lance-mqtt-ws-{uuid.uuid4().hex[:16]}",
            clean_session=True,
            protocol=mqtt.MQTTv311,
            transport=MQTT_WS_TRANSPORT,
            reconnect_on_failure=False,
        )
        client.on_connect = on_connect
        client.on_subscribe = on_subscribe
        client.on_message = on_message
        client.ws_set_options(path=path_value, headers=None)
        # The deadline socket turns paho's per-socket keepalive timeout into an
        # absolute operation deadline covering TCP, HTTP Upgrade, and MQTT.
        client._connect_timeout = min(float(timeout_value), float(WEBSOCKET_KEEPALIVE_SECONDS))
        client.connect(ip_value, port_value, keepalive=WEBSOCKET_KEEPALIVE_SECONDS)

        while time.monotonic() < deadline:
            if stop_event is not None and stop_event.is_set():
                return _error("cancelled", "MQTT WebSocket verification cancelled")
            if (
                state["connack"].get("accepted") is True
                and state["suback"].get("accepted") is True
                and len(state["messages"]) >= count_value
            ):
                break
            remaining = max(0.01, deadline - time.monotonic())
            rc = client.loop(timeout=min(0.2, remaining))
            rc_value = _reason_value(rc)
            if isinstance(rc_value, int) and rc_value != 0:
                # paho's MQTTv311 callback exposes the broker's Not Authorized
                # reason as 135, while the loop may return legacy rc=5.
                auth_refusal = (
                    state["connack"].get("received") is True
                    and state["connack"].get("accepted") is False
                    and rc_value == 5
                )
                if not auth_refusal:
                    state["connection_error"] = f"network_loop_error:{rc_value}"
                break
    except Exception as exc:
        state["connection_error"] = f"{type(exc).__name__}: {str(exc)[:160]}"
    finally:
        if client is not None:
            try:
                client.disconnect()
            except Exception:
                pass
            try:
                client._sock_close()
            except Exception:
                pass

    timed_out = time.monotonic() >= deadline and not (
        state["connack"].get("accepted") is True
        and state["suback"].get("accepted") is True
        and len(state["messages"]) >= count_value
    )
    connack = state["connack"]
    suback = state["suback"]
    auth_required = (
        connack.get("received")
        and not connack.get("accepted")
        and connack.get("reason_code") in {4, 5, 134, 135}
    )
    partial_timeout = (
        timed_out
        and connack.get("received") is True
        and connack.get("accepted") is True
        and suback.get("received") is True
        and suback.get("accepted") is True
        and bool(state["messages"])
        and not state["output_truncated"]
        and state["connection_error"] is None
    )
    successful_exchange = (
        connack.get("received") is True
        and connack.get("accepted") is True
        and suback.get("received") is True
        and suback.get("accepted") is True
        and bool(state["messages"])
        and not state["output_truncated"]
        and state["connection_error"] is None
    )
    if successful_exchange and partial_timeout:
        status, return_code = "timeout", 27
    elif successful_exchange:
        status, return_code = "success", 0
    elif stop_event is not None and stop_event.is_set():
        status, return_code = "cancelled", -2
    elif auth_required:
        status, return_code = "auth_required", 5
    elif timed_out:
        status, return_code = "timeout", 27
    else:
        status, return_code = "error", 1

    result = {
        "ok": successful_exchange,
        "success": successful_exchange,
        "status": status,
        "return_code": return_code,
        "timed_out": timed_out,
        "partial_timeout": partial_timeout,
        "connack": connack,
        "suback": suback,
        "subscribe_mid": state["subscribe_mid"],
        "messages": state["messages"],
        "received_count": len(state["messages"]),
        "requested_count": count_value,
        "output_truncated": state["output_truncated"],
        "error": state["connection_error"],
        "execution_attestation": {
            "output_format": MQTT_WS_OUTPUT_FORMAT,
            "protocol": "MQTTv311",
            "transport": MQTT_WS_TRANSPORT,
            "ip": ip_value,
            "host": ip_value,
            "port": port_value,
            "path": path_value,
            "topic": topic_value,
            "no_auth": True,
            "auth": "no_auth",
            "clean_session": True,
            "reconnect_on_failure": False,
        },
    }
    return json.dumps(result, ensure_ascii=False)
