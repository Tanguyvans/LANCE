"""Strict credential harvesting helpers for Phase 5 intrusion context.

Extracts real credentials from confirmed Phase 4 observations without turning
MQTT telemetry, timestamps (`HH:mm:ss.SSS`), or logger namespaces (`zh:ember`,
`z2m:mqtt`, `uart:ash`) into bogus `user:password` pairs.
"""
from __future__ import annotations

import re

_CRED_PATTERN = re.compile(
    r'(?:user(?:name)?|login|db_user)\s*["\']?\s*[=:]\s*["\']?'
    r'([a-zA-Z0-9_@.\-]+)["\']?[\s,;:"\'(){}]+'
    r'(?:pass(?:word)?|pwd|db_pass)\s*["\']?\s*[=:]\s*["\']?'
    r'([^\s,;"\'(){}\]]+)',
    re.IGNORECASE,
)

# Inline `user:pass` pairs guarded against preceding `:` (blocks HH:mm:ss.SSS -> mm:ss.SSS)
# and URLs (`://`). Only applied to credential-context findings, never raw telemetry blobs.
_SIMPLE_PATTERN = re.compile(
    r'(?<![:\w/])([a-zA-Z][a-zA-Z0-9_\-]{1,31}):'
    r'([a-zA-Z0-9@!#$%^&*_\-+=.]{3,32})(?![:\w/])'
)

_CRED_NOISE = frozenset({
    "http", "https", "ssh", "tcp", "udp", "mqtt", "rtsp", "ftp", "smtp",
    "version", "port", "uid", "gid", "groups", "host", "tor", "mosquitto",
    "server", "service", "protocol", "status", "error", "warning", "info",
    "debug", "type", "name", "value", "level", "mode", "role", "source",
    "target", "device", "sensor", "bridge", "adapter", "network", "state",
    "topic", "payload", "config", "channel", "commit", "format", "date",
    "time", "timestamp", "tst", "qos", "retain", "ieee", "pan", "baudrate",
    "serial", "usb", "tty", "dev", "uart", "zh", "zhc", "z2m", "zigbee",
    "hh", "mm", "ss", "null", "true", "false", "none", "auto", "default",
})

_PWD_NOISE = frozenset({
    "ss.sss", "legacy", "ember", "controller", "mqtt", "ash", "online",
    "offline", "true", "false", "null", "none", "unknown", "enabled",
    "disabled", "auto", "default", "info", "warn", "debug", "error",
})

_BARE_PAIR_VULN_TYPES = frozenset({
    "default_credentials", "weak_credentials", "hardcoded_credentials",
    "credential_exposure", "cleartext_credentials", "auth_bypass",
})

_CRED_CONTEXT_RE = re.compile(
    r"\b(?:credential|password|passwd|login\s+with|auth(?:enticated)?\s+as)\b",
    re.IGNORECASE,
)


def is_plausible_credential(user: str, password: str) -> bool:
    """Return True if `(user, password)` is not obvious log/format/JSON noise."""
    u = user.split("@")[0].strip()
    p = password.strip()
    if not u or not p:
        return False
    if u.lower() in _CRED_NOISE or p.lower() in _PWD_NOISE:
        return False
    if re.fullmatch(r"[HMSyYmd.\-:]+", f"{u}:{p}"):
        return False
    return True


def harvest_credentials_from_text(text: str, *, vuln_type: str = "") -> list[tuple[str, str]]:
    """Extract plausible `(user, password)` pairs from confirmed Phase 4 evidence text."""
    if not text:
        return []
    found: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def _record(raw_user: str, raw_pwd: str) -> None:
        user = raw_user.split("@")[0].strip()
        pwd = raw_pwd.strip()
        if not is_plausible_credential(user, pwd):
            return
        pair = (user, pwd)
        if pair not in seen:
            seen.add(pair)
            found.append(pair)

    for m in _CRED_PATTERN.finditer(text):
        _record(m.group(1), m.group(2))

    vt = (vuln_type or "").strip().casefold()
    allow_bare = vt in _BARE_PAIR_VULN_TYPES or bool(_CRED_CONTEXT_RE.search(text[:400]))
    if allow_bare:
        # Never scan huge raw telemetry/JSON blobs with the bare `word:word` pattern.
        for m in _SIMPLE_PATTERN.finditer(text[:4000]):
            user, pwd = m.group(1), m.group(2)
            if pwd.isdigit():
                continue
            _record(user, pwd)
    return found
