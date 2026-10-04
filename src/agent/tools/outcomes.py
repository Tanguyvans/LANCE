"""Execution failures, separate from the security findings returned by a tool."""
from __future__ import annotations

import json


def tool_execution_failed(tool_name: str, result: object) -> bool:
    """Interpret actual tool results without certifying any vulnerability.

    ssh-audit uses 2/3 for algorithm warnings/failures. mosquitto_sub uses 27
    when its bounded listening window ends, including after receiving messages.
    Preserve these exit codes in evidence; they are not process failures.
    """
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except (TypeError, ValueError):
            return result.startswith("Error")
    if not isinstance(result, dict):
        return False
    if (
        result.get("error") or result.get("exception_type")
        or result.get("ok") is False or result.get("status") == "ERROR"
        or result.get("timed_out") or result.get("cancelled")
    ):
        return True
    code = result.get("return_code")
    if code in (0, None):
        return False
    if tool_name == "ssh_audit" and type(code) is int and code in (2, 3):
        return not bool(str(result.get("stdout") or "").strip())
    if tool_name == "mqtt_listen" and type(code) is int and code == 27:
        return result.get("interpretation") != "listener_timed_out_inspect_captured_messages"
    return True
