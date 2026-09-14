"""Offline SSH request and weak-credential evidence helpers."""
from __future__ import annotations

import ipaddress
import re
from typing import Any


SSH_CREDENTIAL_POLICY_VERSION = "ssh-weak-credentials-v1"
SSH_WEAK_CREDENTIALS = frozenset({
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("root", "root"),
    ("root", "toor"),
    ("ubnt", "ubnt"),
    ("pi", "raspberry"),
    ("admin", ""),
    ("root", ""),
    ("test", "test"),
    ("user", "user"),
})
_TOKEN = r"(?:'[^']*'|\"[^\"]*\"|[^\s]+)"
_SAFE_SSH_OPTIONS = frozenset({
    "StrictHostKeyChecking", "UserKnownHostsFile", "ConnectTimeout",
    "KexAlgorithms", "HostKeyAlgorithms", "Ciphers", "LogLevel",
    "IdentitiesOnly", "PreferredAuthentications", "PubkeyAuthentication",
    "PasswordAuthentication", "BatchMode", "ServerAliveInterval",
    "ServerAliveCountMax", "NumberOfPasswordPrompts", "GlobalKnownHostsFile",
    "CheckHostIP", "VerifyHostKeyDNS", "UpdateHostKeys",
})
_LEGACY_RE = re.compile(
    rf"^sshpass\s+-p\s+(?P<password>{_TOKEN})\s+ssh"
    rf"(?P<options>(?:\s+-o\s+{_TOKEN}|\s+-p\s+\d+|"
    rf"\s+-(?:4|6|A|a|N|T))*)\s+"
    rf"(?P<user>[A-Za-z_][A-Za-z0-9_.-]*)@(?P<target>[^\s]+)\s+"
    rf"(?P<command>'[^']*'|\"[^\"]*\")$"
)


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def _ipv4(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    return str(address) if address.version == 4 else None


def _port(value: Any) -> int | None:
    if value is None or value == "":
        return 22
    if isinstance(value, bool):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 and str(value).strip() == str(port) else None


def _structured(args: dict[str, Any]) -> dict[str, Any] | None:
    # ``host`` is retained only for old archived fixtures; live ssh_exec uses
    # its real ``ip`` field and an invalid supplied ip must not be laundered.
    target_value = args["ip"] if "ip" in args else args.get("host")
    target = _ipv4(target_value)
    port = _port(args.get("port"))
    user = args["user"] if "user" in args else args.get("username")
    password = args.get("password")
    if target is None or port is None:
        return None
    if not isinstance(user, str) or not user or any(char.isspace() for char in user):
        return None
    if password is not None and not isinstance(password, str):
        return None
    return {"host": target, "port": port, "user": user, "password": password}


def _legacy(command_string: Any) -> dict[str, Any] | None:
    if not isinstance(command_string, str):
        return None
    match = _LEGACY_RE.fullmatch(command_string.strip())
    if match is None:
        return None
    raw_password = match.group("password")
    raw_options = match.group("options")
    if any(char in raw_password or char in raw_options for char in "$`;|&<>\\\n"):
        return None
    port_options = re.findall(r"(?:^|\s)-p\s+(\d+)", raw_options)
    if len(port_options) > 1:
        return None
    for option in re.findall(r"(?:^|\s)-o\s+([^\s]+|'[^']*'|\"[^\"]*\")", raw_options):
        option_name = _unquote(option).split("=", 1)[0]
        if option_name not in _SAFE_SSH_OPTIONS:
            return None
    target = _ipv4(match.group("target"))
    port_match = re.search(r"(?:^|\s)-p\s+(\d+)", raw_options)
    port = _port(port_match.group(1)) if port_match else 22
    raw_command = match.group("command")
    if raw_command.startswith('"') and any(char in raw_command for char in "$`"):
        return None
    password = _unquote(raw_password)
    user = match.group("user")
    if target is None or port is None:
        return None
    return {"host": target, "port": port, "user": user, "password": password}


def ssh_request(record: dict[str, Any]) -> dict[str, Any] | None:
    """Extract a strict, offline SSH request from an archived tool record.

    ``command_string`` is intentionally authoritative when present. This
    prevents structured fields from laundering a different legacy destination.
    No shell is executed or interpreted beyond the narrow legacy grammar.
    """
    if not isinstance(record, dict) or record.get("tool") not in {"ssh_exec", "ssh_login"}:
        return None
    args = record.get("args")
    if not isinstance(args, dict):
        return None
    if "command_string" in args:
        return _legacy(args.get("command_string"))
    return _structured(args)


def known_weak_ssh_credential(request: dict[str, Any] | None) -> bool:
    """Whether a parsed SSH request uses one of the finite weak pairs."""
    if not isinstance(request, dict):
        return False
    identity = (request.get("user"), request.get("password"))
    return identity in SSH_WEAK_CREDENTIALS
