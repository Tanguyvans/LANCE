"""Tests for cost_tracker module."""
import time
from unittest.mock import patch

from src.agent.cost_tracker import CostTracker, PhaseUsage


class TestPhaseUsage:
    def test_cost_calculation(self):
        usage = PhaseUsage(agent_name="test", input_tokens=1000, output_tokens=500)
        # Default pricing: 1.0 input + 3.0 output per million
        cost = usage.cost_usd()
        assert cost == (1000 * 1.0 + 500 * 3.0) / 1_000_000

    def test_cost_with_model(self):
        usage = PhaseUsage(agent_name="test", input_tokens=1_000_000, output_tokens=0)
        cost = usage.cost_usd("claude-sonnet-4-20250514")
        assert cost == 3.0  # $3 per million input tokens


class TestCostTracker:
    def test_start_end_phase(self):
        tracker = CostTracker(model="test-model")
        tracker.start_phase("recon")
        tracker.record_turn(100, 50, 2)
        tracker.record_turn(200, 100, 1)
        usage = tracker.end_phase()

        assert usage is not None
        assert usage.agent_name == "recon"
        assert usage.input_tokens == 300
        assert usage.output_tokens == 150
        assert usage.tool_calls == 3
        assert usage.turns == 2
        assert usage.duration_s > 0

    def test_total_cost(self):
        tracker = CostTracker(model="claude-sonnet-4-20250514")
        tracker.start_phase("phase1")
        tracker.record_turn(1_000_000, 0)
        tracker.end_phase()

        tracker.start_phase("phase2")
        tracker.record_turn(0, 1_000_000)
        tracker.end_phase()

        # $3 input + $15 output = $18
        assert tracker.total_cost() == 18.0

    def test_total_tokens(self):
        tracker = CostTracker()
        tracker.start_phase("a")
        tracker.record_turn(100, 50)
        tracker.end_phase()
        tracker.start_phase("b")
        tracker.record_turn(200, 100)
        tracker.end_phase()

        in_tok, out_tok = tracker.total_tokens()
        assert in_tok == 300
        assert out_tok == 150

    def test_summary(self):
        tracker = CostTracker(model="test")
        tracker.start_phase("agent1")
        tracker.record_turn(100, 50, 1)
        tracker.end_phase()

        s = tracker.summary()
        assert s["model"] == "test"
        assert s["total_input_tokens"] == 100
        assert s["total_output_tokens"] == 50
        assert s["total_turns"] == 1
        assert s["total_agent_duration_s"] >= s["wall_clock_duration_s"]
        assert s["total_duration_s"] == s["total_agent_duration_s"]
        assert len(s["phases"]) == 1
        assert s["phases"][0]["agent"] == "agent1"

    def test_record_without_start(self):
        tracker = CostTracker()
        tracker.record_turn(100, 50)  # Should not crash

    def test_end_without_start(self):
        tracker = CostTracker()
        result = tracker.end_phase()
        assert result is None

    def test_print_summary(self, capsys):
        tracker = CostTracker(model="test")
        tracker.start_phase("recon")
        tracker.record_turn(1000, 500, 3)
        tracker.end_phase()
        tracker.print_summary()

        captured = capsys.readouterr()
        assert "COST SUMMARY" in captured.out
        assert "recon" in captured.out
        assert "TOTAL" in captured.out

    def test_multi_model_cost_uses_each_phase_model(self):
        with patch("src.agent.cost_tracker.get_dynamic_pricing", return_value=None):
            tracker = CostTracker(model="openai/gpt-4o")
            tracker.start_phase("phase1")
            tracker.record_turn(1_000_000, 0)
            tracker.end_phase()
            tracker.model = "deepseek/deepseek-chat-v3-0324"
            tracker.start_phase("phase2")
            tracker.record_turn(1_000_000, 0)
            tracker.end_phase()

        assert tracker.total_cost() == 2.77
        assert [phase["model"] for phase in tracker.summary()["phases"]] == [
            "openai/gpt-4o", "deepseek/deepseek-chat-v3-0324"
        ]

    def test_pricing_is_snapshotted_at_phase_start(self):
        with patch("src.agent.cost_tracker.get_dynamic_pricing") as pricing:
            pricing.return_value = {"input": 2.0, "output": 4.0}
            tracker = CostTracker(model="dynamic/model")
            tracker.start_phase("phase")
            tracker.record_turn(1_000_000, 0)
            tracker.end_phase()
            pricing.return_value = {"input": 99.0, "output": 99.0}
            assert tracker.total_cost() == 2.0

    def test_process_denominators_and_schema_are_persisted(self):
        tracker = CostTracker(model="test")
        tracker.start_phase("phase")
        tracker.record_turn(10, 5, tool_call_count=2)
        tracker.record_format_attempt(fallback_used=True)
        tracker.record_validation_result(success=False)
        tracker.record_validation_result(success=True)
        tracker.record_tool_error()
        tracker.end_phase()

        summary = tracker.summary()
        assert summary["metrics_schema_version"] == 2
        assert summary["total_tool_calls"] == 2
        assert summary["total_format_attempts"] == 1
        assert summary["total_format_fallbacks"] == 1
        assert summary["total_validation_attempts"] == 2
        assert summary["total_validation_successes"] == 1
        assert summary["total_validation_failures"] == 1
        assert summary["total_tool_errors"] == 1

    def test_unknown_model_cost_is_explicitly_estimated(self):
        with patch("src.agent.cost_tracker.get_dynamic_pricing", return_value=None):
            tracker = CostTracker(model="local/unknown")
            tracker.start_phase("phase")
            tracker.record_turn(1, 1)
            tracker.end_phase()
            summary = tracker.summary()

        assert summary["cost_is_estimate"] is True
        assert summary["phases"][0]["pricing_source"] == "default_estimate"

    def test_codex_subscription_has_zero_metered_cost(self):
        tracker = CostTracker(model="gpt-5.6-sol", provider="codex")
        tracker.start_phase("phase")
        tracker.record_turn(1_000_000, 500_000)
        tracker.end_phase()

        summary = tracker.summary()
        assert summary["total_cost_usd"] == 0.0
        assert summary["cost_is_estimate"] is False
        assert summary["phases"][0]["pricing_source"] == "subscription"
