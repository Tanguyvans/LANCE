"""Observable action checks and default intrusion finalization."""

def has_observable_actions(data: dict) -> bool:
    summary = data.get("summary", {}) if isinstance(data, dict) else {}
    if not isinstance(summary, dict):
        return False
    return (
        int(summary.get("devices_attempted", 0) or 0) > 0
        or int(summary.get("devices_compromised", 0) or 0) > 0
    )

def set_diagnostic(data: dict, status: str, reason: str) -> None:
    data["status"] = status
    data["blocked_reason"] = reason
    data.setdefault("summary", {})["_note"] = reason

def block_without_actions(data: dict) -> str:
    set_diagnostic(data, "blocked", (
        "No observable Phase 5 intrusion action was recorded; "
        "only context/completion chatter was available."
    ))
    return "blocked:phase5_no_observable_actions"


def finalize_synthesis(data: dict, previous_status: str) -> str:
    if previous_status.split(":", 1)[0] in {"stopped", "budget_exceeded"}:
        set_diagnostic(data, previous_status.split(":", 1)[0], "Phase 5 interrupted; observations retained without campaign completion.")
        return previous_status
    if not has_observable_actions(data):
        return block_without_actions(data)
    missing = "not found" in previous_status or previous_status == "completed"
    reason = "model_deliverable_missing" if missing else "model_deliverable_invalid"
    data["completion"] = {
        "status": "incomplete", "reason": reason,
        "initial_validation_status": previous_status,
        "source": "tool_calls.jsonl",
    }
    set_diagnostic(data, "incomplete", (
        "Phase 5 model deliverable was not finalized. This file retains tool "
        "observations only; it does not validate campaign completion or pivots."
    ))
    return "failed:phase5_completion_missing" if missing else "failed:phase5_completion_invalid"
