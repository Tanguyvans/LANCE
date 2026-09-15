"""Confidential, best-effort diagnostics for provider/model turns.

This module deliberately accepts only metadata.  It is not a second evidence
ledger: prompts, model reasoning, tool arguments, tool results, credentials,
URLs, and exception messages must never enter this sidecar.
"""
from __future__ import annotations

import json
import logging
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


log = logging.getLogger(__name__)

PROVIDER_EVENTS_FILENAME = "provider_events.jsonl"
_MAX_ID = 96
_MAX_REF = 256
_SAFE_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,96}$")
_SAFE_REF = re.compile(
    r"^\.attempts/[A-Za-z0-9_.-]{1,160}/attempt-[0-9a-f]{32}\.[A-Za-z0-9]{1,16}$"
)
_FINISH_REASONS = frozenset({
    "stop", "length", "tool_calls", "error", "content_filter", "function_call",
})
_EVENTS = frozenset({
    "invocation_started", "request", "response", "tool_proposed",
    "tool_executed", "tool_refused", "finalization_entered", "save_outcome",
    "terminal",
})
_RESPONSE_TYPES = frozenset({
    "emptychoices", "emptymessage", "textonly", "tool_calls", "providererror",
    "finish_reasonerror", "length", "malformedargs",
})
_ERROR_KINDS = frozenset({
    "no_user_query", "invalid_tool_arguments", "invalid_request", "transient",
    "network", "timeout", "unknown",
})
_TOOL_REASONS = frozenset({"stop", "tool_budget", "completion_required", "repeated_call", "unavailable", "malformed_args"})
_FINALIZATION_REASONS = frozenset({
    "turn_budget", "textonly", "finish_reasonerror", "emptychoices", "emptymessage", "length", "malformedargs",
    "rejected_save", "data_tool_budget", "repeat_guard", "phase4_conclusive", "recon_ready",
    "recon_completion_required",
})
_OUTCOMES = frozenset({"accepted", "rejected", "success", "error", "returned"})
_CAUSES = frozenset({
    "accepted_save", "rejected_save", "textonly", "emptychoices", "emptymessage",
    "providererror", "stop", "budget", "deadline", "length", "finish_reasonerror", "malformedargs",
    "terminalretryexhausted", "max_turns_exhausted", "unknown_tool", "tool_terminated",
    "callback", "internal", "unknown",
})


def _safe_id(value: Any, *, fallback: str = "unknown") -> str:
    value = str(value) if value is not None else ""
    if len(value) > _MAX_ID or not _SAFE_ID.fullmatch(value):
        return fallback
    return value


def _safe_ref(value: Any) -> str | None:
    if not isinstance(value, str) or not value or len(value) > _MAX_REF:
        return None
    if value.startswith(("/", "\\")) or "\\" in value or not _SAFE_REF.fullmatch(value):
        return None
    if any(part in {".", ".."} for part in value.split("/")):
        return None
    return value


def _safe_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        value = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return value if 0 <= value <= 1_000_000 else None


def _safe_finish_reason(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip().lower()
    return value if value in _FINISH_REASONS else "unknown"


def sanitize_event(
    event: dict[str, Any],
    *,
    provider: Any,
    model: Any,
    invocation_id: Any,
    known_tools: set[str] | frozenset[str],
    phase: Any = None,
    agent: Any = None,
    run_id: Any = None,
) -> dict[str, Any] | None:
    """Build an allowlisted event; unknown or unsafe values are discarded."""
    if not isinstance(event, dict):
        return None
    name = event.get("event")
    if name not in _EVENTS:
        return None
    record: dict[str, Any] = {
        "schema_version": "model.obs1",
        "event": name,
        "provider": _safe_id(provider),
        "model": _safe_id(model),
        "invocation_id": _safe_id(invocation_id),
        "phase": _safe_id(phase, fallback="unknown") if phase is not None else "unknown",
        "agent": _safe_id(agent) if agent is not None else "unknown",
    }
    if run_id is not None:
        record["run_id"] = _safe_id(run_id)
    for key in ("request_num", "attempt", "turn"):
        value = _safe_int(event.get(key))
        if value is not None:
            record[key] = value
    if name == "response":
        response_type = event.get("response_type")
        if response_type in _RESPONSE_TYPES:
            record["response_type"] = response_type
        record["usage_present"] = bool(event.get("usage_present"))
        record["finish_reason"] = _safe_finish_reason(event.get("finish_reason"))
        if response_type == "providererror":
            error_kind = event.get("error_kind")
            record["error_kind"] = error_kind if error_kind in _ERROR_KINDS else "unknown"
            status_code = _safe_int(event.get("status_code"))
            if status_code is not None and 100 <= status_code <= 599:
                record["status_code"] = status_code
    if name in {"tool_proposed", "tool_executed", "tool_refused"}:
        tool_name = event.get("tool_name")
        record["tool_name"] = tool_name if isinstance(tool_name, str) and tool_name in known_tools else "unknown"
        reason = event.get("reason")
        if reason in _TOOL_REASONS:
            record["reason"] = reason
        outcome = event.get("outcome")
        if outcome in _OUTCOMES:
            record["outcome"] = outcome
    if name == "finalization_entered":
        reason = event.get("reason")
        record["reason"] = reason if reason in _FINALIZATION_REASONS else "unknown"
        for key in ("no_tool_stalls", "finalization_requests", "data_tool_calls"):
            value = _safe_int(event.get(key))
            if value is not None:
                record[key] = value
    if name == "save_outcome":
        record["outcome"] = "accepted" if event.get("accepted") is True else "rejected"
        attempt_ref = _safe_ref(event.get("attempt_ref"))
        if attempt_ref is not None:
            record["attempt_ref"] = attempt_ref
    if name == "terminal":
        cause = event.get("cause")
        record["cause"] = cause if cause in _CAUSES else "unknown"
    return record


def append_event(
    run_dir: Path,
    record: dict[str, Any],
    *,
    lock: Any = None,
) -> bool:
    """Append one event without allowing diagnostic I/O to affect a run."""
    path = Path(run_dir) / PROVIDER_EVENTS_FILENAME

    def write() -> bool:
        try:
            root_info = os.lstat(run_dir)
            if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
                return False
            persisted = dict(record)
            persisted["schema_version"] = "model.obs1"
            persisted["timestamp"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            payload = (json.dumps(persisted, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NONBLOCK", 0)
            nofollow = getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(path, flags | nofollow, 0o600)
            try:
                file_info = os.fstat(fd)
                if not stat.S_ISREG(file_info.st_mode):
                    return False
                return os.write(fd, payload) == len(payload)
            finally:
                os.close(fd)
        except (OSError, TypeError, ValueError):
            return False

    try:
        if lock is None:
            return write()
        with lock:
            return write()
    except Exception:
        # Includes unusual lock implementations. Never expose the exception
        # text: this path is observational and must not affect the decision.
        return False


def warn_diagnostic_failure(kind: str) -> None:
    """Log a fixed warning without serialising an exception or sensitive data."""
    safe_kind = kind if isinstance(kind, str) and _SAFE_ID.fullmatch(kind) else "diagnostic"
    log.warning("Provider diagnostic %s unavailable", safe_kind)
