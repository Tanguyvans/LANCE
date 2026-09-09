"""Observed authentication/execution, distinct from contact and vulnerability.

A successful HTTP request is service contact, not machine control. This verdict
is invariant across model profiles. A network pivot needs a separate causal
execution record; it cannot be inferred from two successful logins.
"""
from __future__ import annotations

import json
import re


def result_data(record: dict) -> dict:
    raw = record.get("result")
    if isinstance(raw, dict):
        return raw
    try:
        parsed = json.loads(raw) if isinstance(raw, str) else {}
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def command_access_supported(result: dict) -> bool:
    if any(result.get(key) is False for key in ("success", "authenticated", "ok")) or result.get("error"):
        return False
    rc = result.get("return_code")
    if rc is not None and (isinstance(rc, bool) or rc != 0):
        return False
    stdout = str(result.get("stdout") or result.get("output") or "")
    return (rc == 0 or result.get("success") is True) and bool(
        re.search(r"\buid=\d+\b|__ok__", stdout)
    )


def access_supported(record: dict) -> bool:
    result = result_data(record)
    tool = record.get("tool")
    if tool in {"ssh_login", "ssh_exec"}:
        return command_access_supported(result)
    if tool == "try_credential":
        from src.agent.exploit_evidence import _credential_result_supported
        args = record.get("args")
        return isinstance(args, dict) and _credential_result_supported(result, args)
    return False
