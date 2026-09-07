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
    if not has_observable_actions(data):
        return block_without_actions(data)
    return previous_status
