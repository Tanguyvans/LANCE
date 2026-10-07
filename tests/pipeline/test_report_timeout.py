"""Phase 6: the writing deadline must scale with the number of sections.

Regression test for S12 run 2026-10-07_122920 (partial:timeout): 145
report cards against a fixed 600 s global budget, 75 usable. Sections
are written sequentially, one bounded LLM call each, so the deadline
grows linearly with the workload instead of capping large scenarios.
"""
from src.agent.core import runtime
from src.agent.phases.report.run import report_phase_timeout_s


def test_empty_report_keeps_base_budget(monkeypatch):
    monkeypatch.setattr(runtime, "LOCAL_MOE_REPORT_PHASE_TIMEOUT", 600.0)
    monkeypatch.setattr(runtime, "REPORT_TIMEOUT_PER_SECTION_S", 10.0)
    assert report_phase_timeout_s(0) == 600.0


def test_deadline_grows_with_section_count(monkeypatch):
    monkeypatch.setattr(runtime, "LOCAL_MOE_REPORT_PHASE_TIMEOUT", 600.0)
    monkeypatch.setattr(runtime, "REPORT_TIMEOUT_PER_SECTION_S", 10.0)
    # S12 scale: 145 cards need ~600 + 1450 s, not a fixed 600 s.
    assert report_phase_timeout_s(145) == 2050.0
    assert report_phase_timeout_s(7) == 670.0


def test_operator_base_budget_stays_respected(monkeypatch):
    monkeypatch.setattr(runtime, "LOCAL_MOE_REPORT_PHASE_TIMEOUT", 1200.0)
    monkeypatch.setattr(runtime, "REPORT_TIMEOUT_PER_SECTION_S", 0.0)
    assert report_phase_timeout_s(145) == 1200.0
