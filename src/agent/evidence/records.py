"""Identify probe destinations from arguments, never claim metadata or output.

These helpers do not establish execution or network confinement. In particular,
an address in a script/body is not provenance and a free shell is not a pivot.
"""
from __future__ import annotations

import ipaddress
import shlex
from urllib.parse import urlsplit


def _host(value: object) -> str | None:
    text = str(value or "").strip()
    try:
        if "://" in text:
            text = urlsplit(text).hostname or ""
        return str(ipaddress.ip_address(text.strip("[]")))
    except ValueError:
        return None


def shell_destination(command: str) -> str | None:
    """Recognize a simple outer SSH destination, not nested commands or prose."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    try:
        position = tokens.index("ssh") + 1
    except ValueError:
        return None
    while position < len(tokens):
        token = tokens[position]
        if token in {"-p", "-o", "-i", "-l", "-F", "-J", "-L", "-R", "-D"}:
            position += 2
            continue
        if token.startswith("-"):
            position += 1
            continue
        return _host(token.rsplit("@", 1)[-1])
    return None


def observed_targets(record: dict) -> set[str]:
    args = record.get("args")
    if not isinstance(args, dict):
        return set()
    targets: set[str] = set()
    # A command_string is the executable input of the legacy SSH tool. Do not
    # let unused structured arguments disguise a different shell destination.
    if record.get("tool") == "ssh_login" and args.get("command_string"):
        host = shell_destination(str(args["command_string"]))
        return {host} if host else set()
    for key in ("ip", "target_ip", "device_ip", "target", "host", "broker", "url"):
        value = args.get(key)
        values = str(value or "").replace(",", " ").split() if key == "target" else [value]
        for item in values:
            host = _host(item)
            if host:
                targets.add(host)
    return targets


def has_authentication(args: dict) -> bool:
    """Explicit credentials rule out a claim of unauthenticated access."""
    if any(args.get(key) not in (None, "", False) for key in (
        "password", "auth", "cookies", "cookie", "token",
        "certificate_pem", "private_key_pem",
    )):
        return True
    headers = args.get("headers")
    if isinstance(headers, dict) and any(
        str(key).casefold() in {"authorization", "cookie", "proxy-authorization", "x-api-key"}
        and value for key, value in headers.items()
    ):
        return True
    try:
        return bool(urlsplit(str(args.get("url") or "")).username)
    except ValueError:
        return True
