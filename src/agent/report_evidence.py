"""Pure evidence policy shared by report and context generation.

A model confirmation alone is not enough to enter the verified report. Keep
this policy independent from orchestration, providers, and tool execution.
"""


def phase4_evidence_level(test: dict) -> int:
    """Return a normalized Phase 4 evidence level for report scoping."""
    try:
        return int(test.get("evidence_level", 0) or 0)
    except (TypeError, ValueError):
        return 0


def is_verified_report_finding(test: dict) -> bool:
    """Whether a finding has enough Phase 4 evidence for the main report."""
    return (
        str(test.get("status", "")).upper() == "CONFIRMED"
        and phase4_evidence_level(test) >= 2
    )


def report_phase4_summary(summary: dict, tests: list[dict]) -> dict:
    """Project counters without altering the original evidence artifact."""
    report_summary = dict(summary or {})
    verified_count = sum(1 for test in tests if is_verified_report_finding(test))
    unverified_confirmed = sum(
        1
        for test in tests
        if str(test.get("status", "")).upper() == "CONFIRMED"
        and not is_verified_report_finding(test)
    )
    report_summary["confirmed"] = verified_count
    report_summary["verified_confirmed"] = verified_count
    report_summary["unverified_confirmed"] = unverified_confirmed
    return report_summary
