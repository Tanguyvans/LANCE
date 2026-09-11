"""Small, secret-safe diagnostics for terminal pipeline failures."""
from __future__ import annotations

import os
import re
import traceback
from collections.abc import Iterable, Mapping
from typing import Any


SCHEMA_VERSION = 1
MAX_MESSAGE_LENGTH = 1024
MAX_FRAME_COUNT = 32
MAX_CHAIN_LENGTH = 8
MAX_TEXT_LENGTH = 512

_SENSITIVE_KEY_RE = re.compile(
    r"(?:api[_-]?key|access[_-]?token|refresh[_-]?token|auth(?:orization)?|"
    r"pass(?:word|wd)?|secret|credential|private[_-]?key|token)",
    re.IGNORECASE,
)
_SENSITIVE_QUERY_RE = re.compile(
    r"(?P<prefix>[?&])(?P<key>(?:api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"auth(?:orization)?|pass(?:word|wd)?|secret|credential|token))"
    r"=(?P<value>[^&#\s]*)",
    re.IGNORECASE,
)
_SENSITIVE_QUOTED_ASSIGNMENT_RE = re.compile(
    r"(?P<prefix>[\"']?(?:api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"auth(?:orization)?|pass(?:word|wd)?|secret|credential|private[_ -]?key|"
    r"token)[\"']?\s*[:=]\s*)(?P<quote>[\"'])"
    r"(?P<value>(?:\\.|(?!(?P=quote))[^\\])*)(?P=quote)",
    re.IGNORECASE | re.DOTALL,
)
_SENSITIVE_UNCLOSED_QUOTED_ASSIGNMENT_RE = re.compile(
    r"(?P<prefix>[\"']?(?:api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"auth(?:orization)?|pass(?:word|wd)?|secret|credential|private[_ -]?key|"
    r"token)[\"']?\s*[:=]\s*)(?P<quote>[\"'])"
    r"(?P<value>(?:\\.|(?!(?P=quote))[^\\])*)\\?\Z",
    re.IGNORECASE | re.DOTALL,
)
_SENSITIVE_BARE_ASSIGNMENT_RE = re.compile(
    r"(?P<prefix>[\"']?(?:api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"auth(?:orization)?|pass(?:word|wd)?|secret|credential|private[_ -]?key|"
    r"token)[\"']?\s*[:=]\s*)(?P<value>[^,\s\"'}&]+)",
    re.IGNORECASE,
)
_AUTH_ASSIGNMENT_RE = re.compile(
    r"(?P<prefix>[\"']?authorization[\"']?\s*[:=]\s*)"
    r"(?P<value>(?:Bearer|Basic)\s+[^,\s}\"']+)",
    re.IGNORECASE,
)
_URL_USERINFO_RE = re.compile(
    r"(?P<prefix>\b[a-z][a-z0-9+.-]*://)(?P<userinfo>[^/\s@]+)@",
    re.IGNORECASE,
)
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[^,\s}]+")
_BASIC_RE = re.compile(r"(?i)\bBasic\s+[^,\s}]+")
_KNOWN_KEY_RE = re.compile(
    r"(?i)\b(?:sk-(?:proj-)?[a-z0-9_-]{8,}|rk-[a-z0-9_-]{8,}|"
    r"AIza[a-z0-9_-]{20,}|xai-[a-z0-9_-]{8,}|gsk_[a-z0-9_-]{8,}|"
    r"eyJ[a-z0-9_-]{20,}\.[a-z0-9_-]{10,}\.[a-z0-9_-]{10,})\b"
)

# Only named credential variables are inspected.  This deliberately avoids
# serializing or iterating over the full environment.
_KNOWN_SECRET_ENV_NAMES = frozenset({
    "OPENROUTER_API_KEY",
    "MINIMAX_API_KEY",
    "GLM_API_KEY",
    "DASHSCOPE_API_KEY",
    "NVD_API_KEY",
    "VOYAGE_API_KEY",
    "LANCE_ADMIN_TOKEN",
    "LANCE_CONTROLLER_TOKEN",
    "PROXMOX_TOKEN",
    "TAILSCALE_AUTHKEY",
})


def _bounded_text(value: object, *, limit: int = MAX_TEXT_LENGTH) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value:
        return None
    return value[:limit]


def _text_value(value: object) -> str | None:
    """Return text without truncating before secret replacement."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _redact_text(value: str, secret_values: Iterable[str] = ()) -> str:
    """Redact credentials without attempting to interpret arbitrary payloads."""
    # Redact the complete value first.  Truncating first can expose a secret
    # whose prefix starts just before the output boundary.
    text = value
    for secret in sorted(
        {item for item in secret_values if isinstance(item, str) and item},
        key=len,
        reverse=True,
    ):
        text = text.replace(secret, "[REDACTED]")
    text = _URL_USERINFO_RE.sub(r"\g<prefix>[REDACTED]@", text)
    text = _SENSITIVE_QUERY_RE.sub(
        lambda match: f"{match.group('prefix')}{match.group('key')}=[REDACTED]",
        text,
    )
    text = _SENSITIVE_QUOTED_ASSIGNMENT_RE.sub(
        lambda match: (
            f"{match.group('prefix')}{match.group('quote')}[REDACTED]"
            f"{match.group('quote')}"
        ),
        text,
    )
    text = _SENSITIVE_UNCLOSED_QUOTED_ASSIGNMENT_RE.sub(
        lambda match: f"{match.group('prefix')}{match.group('quote')}[REDACTED]",
        text,
    )
    text = _AUTH_ASSIGNMENT_RE.sub(
        lambda match: f"{match.group('prefix')}[REDACTED]",
        text,
    )
    text = _SENSITIVE_BARE_ASSIGNMENT_RE.sub(
        lambda match: f"{match.group('prefix')}[REDACTED]",
        text,
    )
    text = _BEARER_RE.sub("Bearer [REDACTED]", text)
    text = _BASIC_RE.sub("Basic [REDACTED]", text)
    text = _KNOWN_KEY_RE.sub("[REDACTED]", text)
    return text[:MAX_MESSAGE_LENGTH]


def _collect_sensitive_config(value: object, *, sensitive: bool = False) -> set[str]:
    """Collect only values under credential-shaped config keys."""
    found: set[str] = set()
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_sensitive = isinstance(key, str) and bool(_SENSITIVE_KEY_RE.search(key))
            found.update(_collect_sensitive_config(item, sensitive=sensitive or key_sensitive))
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            found.update(_collect_sensitive_config(item, sensitive=sensitive))
    elif sensitive:
        item = _text_value(value)
        if item is not None:
            found.add(item)
    return found


def configured_secret_values(provider: object | None = None, *configs: object) -> set[str]:
    """Return known credential values without exposing the environment itself."""
    values = {
        value for name in _KNOWN_SECRET_ENV_NAMES
        if (value := os.environ.get(name))
    }
    for config in configs:
        values.update(_collect_sensitive_config(config))

    if provider is not None:
        for owner in (provider, getattr(provider, "client", None)):
            try:
                value = _text_value(getattr(owner, "api_key", None))
            except BaseException:
                value = None
            if value is not None:
                values.add(value)
    return values


def _safe_message(exc: BaseException, secret_values: Iterable[str]) -> str | None:
    body = getattr(exc, "body", None)
    if isinstance(body, Mapping):
        error = body.get("error")
        source = error if isinstance(error, Mapping) else body
        message = _text_value(source.get("message"))
        if message is not None:
            return _redact_text(message, secret_values)

    # Status errors may include the complete response body in __str__.
    # Prefer the structured message above; never stringify an opaque body,
    # regardless of the provider or SDK that produced it.
    name = type(exc).__name__
    if body is not None:
        return None

    message = _text_value(getattr(exc, "message", None))
    if message is None and len(getattr(exc, "args", ())) == 1:
        message = _text_value(exc.args[0])
    if message is None:
        try:
            message = _text_value(str(exc))
        except BaseException:
            message = None
    if message is None and name in {"APITimeoutError", "ReadTimeout", "Timeout"}:
        message = "request timed out"
    return _redact_text(message, secret_values) if message is not None else None


def _status_code(exc: BaseException) -> int | None:
    for owner in (exc, getattr(exc, "response", None)):
        try:
            value = getattr(owner, "status_code", None)
        except BaseException:
            value = None
        if isinstance(value, int) and not isinstance(value, bool) and 100 <= value <= 599:
            return value
    return None


def _error_type(exc: BaseException, secret_values: Iterable[str]) -> str | None:
    body = getattr(exc, "body", None)
    if isinstance(body, Mapping):
        error = body.get("error")
        source = error if isinstance(error, Mapping) else body
        value = _text_value(source.get("type"))
        if value is not None:
            return _redact_text(value, secret_values)
    return None


def _traceback_frames(exc: BaseException, secret_values: Iterable[str]) -> list[dict[str, object]]:
    frames: list[dict[str, object]] = []
    try:
        # A deep provider/worker stack is most useful at its failure site.
        extracted = traceback.extract_tb(exc.__traceback__, limit=-MAX_FRAME_COUNT)
    except BaseException:
        extracted = []
    for frame in extracted:
        function = _bounded_text(frame.name, limit=128) or "<unknown>"
        frames.append({
            "file": _redact_text(str(frame.filename), secret_values)[:MAX_TEXT_LENGTH],
            "line": int(frame.lineno),
            "function": _redact_text(function, secret_values),
        })
    return frames


def _chain_entries(exc: BaseException, secret_values: Iterable[str]) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    seen: set[int] = set()
    current: BaseException | None = exc
    relation = "primary"
    while current is not None and len(entries) < MAX_CHAIN_LENGTH and id(current) not in seen:
        seen.add(id(current))
        entry: dict[str, object] = {
            "relation": relation,
            "exception_class": type(current).__name__[:128],
            "exception_module": str(getattr(type(current), "__module__", ""))[:MAX_TEXT_LENGTH],
            "message": _safe_message(current, secret_values),
            "traceback": _traceback_frames(current, secret_values),
        }
        status = _status_code(current)
        if status is not None:
            entry["status_code"] = status
        error_type = _error_type(current, secret_values)
        if error_type is not None:
            entry["error_type"] = error_type
        entries.append(entry)

        cause = current.__cause__
        if cause is not None:
            relation = "cause"
        elif not current.__suppress_context__:
            cause = current.__context__
            relation = "context"
        else:
            cause = None
        current = cause
    return entries


def build_run_error_diagnostic(
    exc: BaseException,
    *,
    phase: str | int | None,
    secret_values: Iterable[str] = (),
) -> dict[str, Any]:
    """Build a bounded diagnostic containing no source lines, locals, or bodies."""
    secrets = tuple(secret_values)
    chain = _chain_entries(exc, secrets)
    primary = chain[0] if chain else {
        "exception_class": type(exc).__name__[:128],
        "exception_module": str(getattr(type(exc), "__module__", ""))[:MAX_TEXT_LENGTH],
        "message": None,
        "traceback": [],
    }
    diagnostic: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "phase": _bounded_text(str(phase), limit=128) if phase is not None else None,
        "exception_class": primary.get("exception_class"),
        "exception_module": primary.get("exception_module"),
        "message": primary.get("message"),
        "traceback": primary.get("traceback", []),
        "exception_chain": chain,
    }
    for key in ("status_code", "error_type"):
        if key in primary:
            diagnostic[key] = primary[key]
    return diagnostic
