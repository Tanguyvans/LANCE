"""Phase 4: recovered probe transients must not degrade the run verdict.

Regression test for S7 run 2026-10-07_102501 (partial): SSH weak-cipher
probes failed once, succeeded on retry, the findings were CONFIRMED, yet
the stale diagnostics flipped the phase to executed_with_worker_errors.
Diagnostics stay preserved as information; only an unconfirmed verdict
with standing diagnostics degrades the phase.
"""
from types import SimpleNamespace

from src.agent.phases.verification.contract import unconfirmed_with_diagnostics


def _run_with(error_ids=()):
    return SimpleNamespace(
        _phase4_execution_errors={vid: [{"stage": "rules_probe", "kind": "tool_error"}] for vid in error_ids},
        _phase4_execution_status="completed",
    )


def test_confirmed_verdict_with_old_diagnostics_does_not_degrade():
    run = _run_with(error_ids=("VULN-013",))
    assert unconfirmed_with_diagnostics(run, "VULN-013", {"status": "CONFIRMED"}) is False
    # Diagnostics are preserved as information, the phase stays completed.
    assert run._phase4_execution_errors["VULN-013"] != []


def test_unconfirmed_verdict_with_diagnostics_degrades():
    run = _run_with(error_ids=("VULN-017",))
    assert unconfirmed_with_diagnostics(run, "VULN-017", {"status": "FAILED"}) is True


def test_clean_candidate_never_degrades():
    run = _run_with()
    assert unconfirmed_with_diagnostics(run, "VULN-001", {"status": "CONFIRMED"}) is False
    assert unconfirmed_with_diagnostics(run, "VULN-002", {"status": "FAILED"}) is False
    assert unconfirmed_with_diagnostics(run, "VULN-003", None) is False
