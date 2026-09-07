"""Derive terminal run state from the existing phase statuses."""


def run_status(results: dict[str, str], termination: str | None = None) -> str:
    if termination:
        return termination
    states = {value.partition(":")[0] for value in results.values()}
    if "stopped" in states:
        return "stopped"
    # Unknown statuses must never silently count as successful execution.
    if states - {"completed", "skipped", "blocked", "partial", "executed_with_worker_errors"}:
        return "failed"
    if "blocked" in states or "skipped:prerequisites" in results.values():
        return "blocked"
    if states & {"partial", "executed_with_worker_errors"}:
        return "partial"
    if states <= {"skipped"}:
        return "skipped"
    return "completed"


def prerequisite_status_allows_artifact(value: str | None) -> bool:
    """A skip can reuse an artifact, but is never evidence of its existence."""
    return value is None or value == "executed_with_worker_errors" or (
        value.partition(":")[0] in {"completed", "skipped"}
    )
