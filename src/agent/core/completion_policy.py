"""Pure state transitions for bounded pre-finalization continuations."""
from __future__ import annotations

from dataclasses import dataclass
import json


NON_ACTION_TOOL_NAMES = frozenset({
    "read_deliverable",
    "list_deliverables",
    "aggregate_device_results",
})
ACTION_REFUSAL_ERROR_KINDS = frozenset({
    "invalid_tool_arguments",
    "intrusion_scope_unavailable",
    "intrusion_target_unverifiable",
    "intrusion_target_out_of_scope",
    "intrusion_command_out_of_scope",
    "intrusion_command_destination_unverifiable",
    "intrusion_command_hostname_unverifiable",
    "unverifiable_execution_scope",
    "run_stopped",
    "benchmark_memory_disabled",
})


def real_action_result(result: str) -> bool:
    """Recognize usable activity for continuation, never proof of an access."""
    if not isinstance(result, str) or not result.strip():
        return False
    if result.startswith("Error executing "):
        return False
    try:
        payload = json.loads(result)
    except (TypeError, ValueError, json.JSONDecodeError):
        return False
    if isinstance(payload, list):
        return bool(payload)
    if not isinstance(payload, dict) or not payload:
        return False
    if payload.get("error_kind") in ACTION_REFUSAL_ERROR_KINDS:
        return False
    if payload.get("ok") is True or payload.get("success") is True:
        return True
    generic_failure_keys = {"ok", "success", "error", "error_kind", "status"}
    return any(key not in generic_failure_keys for key in payload)


@dataclass
class CompletionPolicy:
    """Bound one invocation's recovery before terminal-only finalization."""

    max_continuations: int = 2
    continuation_count: int = 0
    incident_open: bool = False
    finalization_only: bool = False

    def request_continuation(self, *, budget_reserved: bool) -> bool:
        """Open one continuation, or latch terminal-only finalization."""
        if (
            self.finalization_only
            or budget_reserved
            or self.incident_open
            or self.continuation_count >= self.max_continuations
        ):
            self.finalization_only = True
            return False
        self.continuation_count += 1
        self.incident_open = True
        return True

    def action_executed(
        self,
        tool_name: str,
        terminal_tool: str | None,
        *,
        result: str,
    ) -> None:
        """Reset only after a real non-terminal action returned an observation."""
        if (
            not self.finalization_only
            and tool_name != terminal_tool
            and tool_name not in NON_ACTION_TOOL_NAMES
            and real_action_result(result)
        ):
            self.incident_open = False

    def enter_finalization(self) -> None:
        """Latch terminal-only mode permanently for this invocation."""
        self.finalization_only = True
