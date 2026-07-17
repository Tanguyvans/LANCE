"""Positive tool and argument policy for evaluator-owned sealed workers.

The public harness intentionally keeps a broad, extensible YAML tool catalogue.
That catalogue is not a security boundary: a positional value beginning with
``-`` can become a new CLI option, and several tools deliberately accept local
paths or arbitrary client commands.  Sealed runs therefore expose only this
audited surface and validate every network destination against the controller-
issued CIDRs before invoking a handler.
"""

from __future__ import annotations

import re
from ipaddress import ip_address, ip_network
from typing import Mapping
from urllib.parse import urlsplit


class SealedToolPolicyError(ValueError):
    """Raised before an unsafe sealed tool call reaches its implementation."""


_NO_ARGS = frozenset()

# Explicit argument names are part of the security policy.  In particular,
# unknown YAML arguments (including the loader's implicit ``timeout`` escape
# hatch) are rejected rather than silently forwarded.
_TOOL_ARGUMENTS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    # In-memory discovery graph.
    "get_network_topology": (_NO_ARGS, _NO_ARGS),
    "get_device_info": (frozenset({"device_id"}), frozenset({"device_id"})),
    "get_attack_surface": (_NO_ARGS, _NO_ARGS),
    "get_attack_paths": (_NO_ARGS, _NO_ARGS),
    "get_risk_scores": (_NO_ARGS, _NO_ARGS),
    "get_graph_disbalance": (_NO_ARGS, _NO_ARGS),
    # Run-local artifacts and static, bundled skills.
    "save_deliverable": (
        frozenset({"filename", "content"}),
        frozenset({"content"}),
    ),
    "read_deliverable": (frozenset({"filename"}), frozenset({"filename"})),
    "list_deliverables": (_NO_ARGS, _NO_ARGS),
    "aggregate_device_results": (frozenset({"pattern"}), _NO_ARGS),
    "list_skills": (_NO_ARGS, _NO_ARGS),
    "load_skill": (frozenset({"skill_name"}), frozenset({"skill_name"})),
    "decode_value": (
        frozenset({"value", "kind"}),
        frozenset({"value", "kind"}),
    ),
    # Audited network clients. Broad scanners, local-path consumers, generic
    # shells and arbitrary database/Redis clients are intentionally absent.
    "nmap_discovery": (frozenset({"target"}), frozenset({"target"})),
    "nmap_scan": (
        frozenset({"target", "ports", "skip_discovery", "scripts", "udp_scan"}),
        frozenset({"target"}),
    ),
    "modbus_scan": (
        frozenset({"target", "skip_discovery"}),
        frozenset({"target"}),
    ),
    "ssh_audit": (
        frozenset({"host", "port"}),
        frozenset({"host"}),
    ),
    "http_get": (frozenset({"url"}), frozenset({"url"})),
    "ftp_list": (
        frozenset({"url", "user"}),
        frozenset({"url"}),
    ),
    "mqtt_listen": (
        frozenset({"broker", "topic", "count", "timeout", "username", "password"}),
        frozenset({"broker"}),
    ),
    "traceroute": (
        frozenset({"target", "max_hops"}),
        frozenset({"target"}),
    ),
    "http_request": (
        frozenset({
            "url", "method", "headers", "body", "follow_redirects",
            "verify_tls", "timeout",
        }),
        frozenset({"url"}),
    ),
    "tcp_send": (
        frozenset({"host", "port", "payload_hex", "recv_bytes", "timeout"}),
        frozenset({"host", "port", "payload_hex"}),
    ),
    "udp_send": (
        frozenset({"host", "port", "payload", "encoding", "recv_bytes", "timeout"}),
        frozenset({"host", "port", "payload"}),
    ),
    "mtls_request": (
        frozenset({
            "url", "certificate_pem", "private_key_pem", "ca_pem", "method",
            "headers", "body", "timeout",
        }),
        frozenset({"url", "certificate_pem", "private_key_pem"}),
    ),
    "tls_inspect": (
        frozenset({"host", "port", "sni"}),
        frozenset({"host"}),
    ),
    "modbus_write": (
        frozenset({"target", "register", "value", "port", "unit_id"}),
        frozenset({"target", "register", "value"}),
    ),
    "try_credential": (
        frozenset({"ip", "service", "user", "password", "port"}),
        frozenset({"ip", "service", "user", "password"}),
    ),
    "ssh_exec": (
        frozenset({"ip", "user", "password", "command", "port"}),
        frozenset({"ip", "user", "password", "command"}),
    ),
}

SEALED_ALLOWED_TOOLS = frozenset(_TOOL_ARGUMENTS)

_CLI_STRING_FIELDS: dict[str, frozenset[str]] = {
    "nmap_discovery": frozenset({"target"}),
    "nmap_scan": frozenset({"target", "ports", "scripts"}),
    "modbus_scan": frozenset({"target"}),
    "ssh_audit": frozenset({"host"}),
    "http_get": frozenset({"url"}),
    "ftp_list": frozenset({"url", "user"}),
    "mqtt_listen": frozenset({"broker", "topic", "username", "password"}),
    "traceroute": frozenset({"target"}),
    "try_credential": frozenset({"ip", "service", "user", "password"}),
    "ssh_exec": frozenset({"ip", "user", "password", "command"}),
}

_SAFE_NMAP_SCRIPTS = frozenset(
    {
        "banner",
        "http-auth",
        "http-title",
        "mysql-empty-password",
        "ssh-auth-methods",
        "snmp-brute",
    }
)
_PORTS_RE = re.compile(r"^\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*$")
_SKILL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_.-]{0,63}$")
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$")
_METHODS = frozenset({"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"})
_SERVICES = frozenset({"ssh", "http", "ftp", "mqtt", "telnet", "redis", "mysql"})


def _string(value: object, field: str, *, max_length: int = 4096, empty: bool = False) -> str:
    if not isinstance(value, str) or (not empty and not value):
        raise SealedToolPolicyError(f"{field} must be a string")
    if len(value) > max_length or "\x00" in value:
        raise SealedToolPolicyError(f"{field} is too long or contains NUL")
    return value


def _cli_string(value: object, field: str, *, empty: bool = False) -> str:
    result = _string(value, field, empty=empty)
    if result.startswith("-"):
        raise SealedToolPolicyError(f"{field} may not begin with an option prefix")
    if any(ord(char) < 32 or ord(char) == 127 for char in result):
        raise SealedToolPolicyError(f"{field} contains control characters")
    return result


def _integer(value: object, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise SealedToolPolicyError(f"{field} must be an integer in {minimum}..{maximum}")
    return value


def _boolean(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise SealedToolPolicyError(f"{field} must be a boolean")
    return value


def _networks(cidrs: tuple[str, ...] | list[str]) -> tuple[object, ...]:
    try:
        result = tuple(ip_network(cidr, strict=True) for cidr in cidrs)
    except ValueError as exc:
        raise SealedToolPolicyError("sealed scope contains an invalid CIDR") from exc
    if not result:
        raise SealedToolPolicyError("sealed scope contains no authorized CIDR")
    return result


def _ip_in_scope(raw: object, field: str, networks: tuple[object, ...]) -> None:
    value = _cli_string(raw, field)
    try:
        address = ip_address(value)
    except ValueError as exc:
        raise SealedToolPolicyError(f"{field} must be a literal IP address") from exc
    if not any(address.version == network.version and address in network for network in networks):
        raise SealedToolPolicyError(f"{field} is outside the sealed scope")


def _targets_in_scope(raw: object, field: str, networks: tuple[object, ...]) -> None:
    value = _cli_string(raw, field)
    targets = [part for part in re.split(r"[\s,]+", value) if part]
    if not targets:
        raise SealedToolPolicyError(f"{field} contains no target")
    for target in targets:
        if target.startswith("-"):
            raise SealedToolPolicyError(f"{field} contains an injected option")
        try:
            if "/" in target:
                candidate = ip_network(target, strict=True)
                allowed = any(
                    candidate.version == network.version and candidate.subnet_of(network)
                    for network in networks
                )
            else:
                address = ip_address(target)
                allowed = any(
                    address.version == network.version and address in network
                    for network in networks
                )
        except ValueError as exc:
            raise SealedToolPolicyError(
                f"{field} accepts only literal IP addresses or canonical CIDRs"
            ) from exc
        if not allowed:
            raise SealedToolPolicyError(f"{field} contains a target outside the sealed scope")


def _url_in_scope(raw: object, field: str, networks: tuple[object, ...], schemes: set[str]) -> None:
    value = _cli_string(raw, field)
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise SealedToolPolicyError(f"{field} is not a valid URL") from exc
    if parsed.scheme.lower() not in schemes or not parsed.hostname:
        raise SealedToolPolicyError(f"{field} uses a forbidden URL scheme")
    if parsed.username is not None or parsed.password is not None:
        raise SealedToolPolicyError(f"{field} may not contain URL credentials")
    if port is not None:
        _integer(port, f"{field}.port", 1, 65535)
    _ip_in_scope(parsed.hostname, f"{field}.host", networks)


def _headers(value: object) -> None:
    if not isinstance(value, Mapping) or len(value) > 64:
        raise SealedToolPolicyError("headers must be an object with at most 64 entries")
    for name, header_value in value.items():
        if not isinstance(name, str) or not _HEADER_NAME_RE.fullmatch(name):
            raise SealedToolPolicyError("headers contains an invalid name")
        text = _string(header_value, f"headers.{name}", max_length=8192, empty=True)
        if "\r" in text or "\n" in text:
            raise SealedToolPolicyError(f"headers.{name} contains a line break")


def _validate_common(tool_name: str, kwargs: Mapping[str, object]) -> dict[str, object]:
    if tool_name not in _TOOL_ARGUMENTS:
        raise SealedToolPolicyError(f"tool {tool_name!r} is not available in sealed mode")
    if not isinstance(kwargs, Mapping) or not all(isinstance(key, str) for key in kwargs):
        raise SealedToolPolicyError("tool arguments must be an object with string keys")
    allowed, required = _TOOL_ARGUMENTS[tool_name]
    unknown = frozenset(kwargs) - allowed
    missing = required - frozenset(kwargs)
    if unknown:
        raise SealedToolPolicyError(f"{tool_name} contains unknown arguments: {sorted(unknown)}")
    if missing:
        raise SealedToolPolicyError(f"{tool_name} is missing arguments: {sorted(missing)}")
    result = dict(kwargs)
    for field in _CLI_STRING_FIELDS.get(tool_name, _NO_ARGS):
        if field in result:
            _cli_string(result[field], f"{tool_name}.{field}", empty=field in {"password", "user"})
    return result


def validate_sealed_tool_call(
    tool_name: str,
    kwargs: Mapping[str, object],
    ingress_cidrs: tuple[str, ...] | list[str],
) -> dict[str, object]:
    """Validate and return the exact kwargs safe to pass to a sealed handler."""

    result = _validate_common(tool_name, kwargs)
    networks = _networks(ingress_cidrs)

    if tool_name in {"nmap_discovery", "nmap_scan", "modbus_scan"}:
        _targets_in_scope(result["target"], f"{tool_name}.target", networks)
    if tool_name in {"traceroute"}:
        _ip_in_scope(result["target"], f"{tool_name}.target", networks)
    for name, field in {
        "ssh_audit": "host",
        "mqtt_listen": "broker",
        "tcp_send": "host",
        "udp_send": "host",
        "tls_inspect": "host",
        "try_credential": "ip",
        "ssh_exec": "ip",
        "modbus_write": "target",
    }.items():
        if tool_name == name:
            _ip_in_scope(result[field], f"{tool_name}.{field}", networks)

    if tool_name in {"http_get", "http_request"}:
        _url_in_scope(result["url"], f"{tool_name}.url", networks, {"http", "https"})
    elif tool_name == "ftp_list":
        _url_in_scope(result["url"], "ftp_list.url", networks, {"ftp"})
    elif tool_name == "mtls_request":
        _url_in_scope(result["url"], "mtls_request.url", networks, {"https"})

    if tool_name == "nmap_scan":
        if "ports" in result:
            ports = _cli_string(result["ports"], "nmap_scan.ports")
            if not _PORTS_RE.fullmatch(ports):
                raise SealedToolPolicyError("nmap_scan.ports is not a bounded port list")
            port_count = 0
            for item in ports.split(","):
                bounds = [int(part) for part in item.split("-")]
                if any(not 1 <= part <= 65535 for part in bounds) or bounds != sorted(bounds):
                    raise SealedToolPolicyError("nmap_scan.ports contains an invalid range")
                port_count += bounds[-1] - bounds[0] + 1
            if port_count > 1024:
                raise SealedToolPolicyError("nmap_scan.ports exceeds the 1024-port sealed limit")
        if "scripts" in result:
            scripts = set(_cli_string(result["scripts"], "nmap_scan.scripts").split(","))
            if not scripts or not scripts.issubset(_SAFE_NMAP_SCRIPTS):
                raise SealedToolPolicyError("nmap_scan.scripts is not in the sealed allowlist")
        for field in ("skip_discovery", "udp_scan"):
            if field in result:
                _boolean(result[field], f"nmap_scan.{field}")
        if result.get("udp_scan") is True and "ports" not in result:
            raise SealedToolPolicyError("nmap_scan.udp_scan requires an explicit port list")
    elif tool_name == "modbus_scan" and "skip_discovery" in result:
        _boolean(result["skip_discovery"], "modbus_scan.skip_discovery")

    for field in ("port",):
        if field in result:
            _integer(result[field], f"{tool_name}.{field}", 1, 65535)
    for field, minimum, maximum in (
        ("timeout", 1, 30),
        ("max_hops", 1, 30),
        ("count", 1, 100),
        ("recv_bytes", 0, 65536),
    ):
        if field in result:
            _integer(result[field], f"{tool_name}.{field}", minimum, maximum)
    if tool_name == "modbus_write":
        _integer(result["register"], "modbus_write.register", 0, 65535)
        _integer(result["value"], "modbus_write.value", 0, 65535)
        if "unit_id" in result:
            _integer(result["unit_id"], "modbus_write.unit_id", 1, 247)

    if tool_name == "http_request":
        # Omitted means false in sealed mode, even though the public handler's
        # convenience default follows redirects.
        if result.get("follow_redirects", False) is not False:
            raise SealedToolPolicyError("http_request redirects are disabled in sealed mode")
        result["follow_redirects"] = False
        if "verify_tls" in result:
            _boolean(result["verify_tls"], "http_request.verify_tls")
    if tool_name in {"http_request", "mtls_request"}:
        method = result.get("method", "GET")
        if not isinstance(method, str) or method.upper() not in _METHODS:
            raise SealedToolPolicyError(f"{tool_name}.method is not allowed")
        if "headers" in result:
            _headers(result["headers"])
        if "body" in result:
            _string(result["body"], f"{tool_name}.body", max_length=65536, empty=True)

    if tool_name == "save_deliverable":
        if "filename" in result:
            _string(result["filename"], "save_deliverable.filename", max_length=255)
        _string(
            result["content"],
            "save_deliverable.content",
            max_length=1_000_000,
            empty=True,
        )
    elif tool_name == "decode_value":
        _string(result["value"], "decode_value.value", max_length=131_072, empty=True)

    if tool_name == "tcp_send":
        payload = _string(result["payload_hex"], "tcp_send.payload_hex", max_length=131070, empty=True)
        if payload and (len(payload.replace(" ", "")) % 2 or not re.fullmatch(r"[0-9A-Fa-f ]+", payload)):
            raise SealedToolPolicyError("tcp_send.payload_hex is not hexadecimal")
    elif tool_name == "udp_send":
        encoding = result.get("encoding", "text")
        if encoding not in {"text", "hex"}:
            raise SealedToolPolicyError("udp_send.encoding must be text or hex")
        _string(result["payload"], "udp_send.payload", max_length=131070, empty=True)
    elif tool_name == "try_credential":
        if result["service"] not in _SERVICES:
            raise SealedToolPolicyError("try_credential.service is not allowed")
        if result["user"] and not _USERNAME_RE.fullmatch(result["user"]):
            raise SealedToolPolicyError("try_credential.user is not a safe username")
    elif tool_name == "ssh_exec":
        if not _USERNAME_RE.fullmatch(result["user"]):
            raise SealedToolPolicyError("ssh_exec.user is not a safe username")
        _string(result["command"], "ssh_exec.command", max_length=4096)
    elif tool_name == "load_skill":
        if not isinstance(result["skill_name"], str) or not _SKILL_RE.fullmatch(result["skill_name"]):
            raise SealedToolPolicyError("load_skill.skill_name is invalid")
    elif tool_name == "decode_value":
        if not isinstance(result["kind"], str) or result["kind"] not in {"base64", "url", "jwt", "hex"}:
            raise SealedToolPolicyError("decode_value.kind is not allowed")

    return result
