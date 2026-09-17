import pytest
from src.agent.report_evidence import verification_state
from src.agent.phases.verification.evidence import verification_attempted


@pytest.mark.parametrize("records,expected", [
    ([], False),
    ([{"tool": "save_deliverable", "result": "ok"}], False),
    ([{"tool": "get_device_info", "result": "{}"}], False),
    ([{"tool": "python_exec", "result": '{"error_kind":"unverifiable_execution_scope"}'}], False),
    ([{"tool": "http_get", "result": '{"return_code":28,"stderr":"timeout"}'}], True),
    ([{"tool": "ssh_audit", "result": "observations"}], True),
])
def test_effective_attempt(records, expected):
    assert verification_attempted(records) is expected


def test_no_attempt_is_distinct_from_error_and_proof_wins():
    entry = {"status": "ERROR", "verification_attempted": False, "execution_error_count": 1}
    assert verification_state(entry) == "not_tested"
    assert verification_state({"status": "ERROR"}) == "error"  # historical unknown
    assert verification_state({**entry, "status": "CONFIRMED", "evidence_level": 3}) == "confirmed"
    assert verification_state({"status": "FAILED", "verification_attempted": True}) == "inconclusive"
