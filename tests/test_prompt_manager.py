"""Tests for prompt_manager module."""
import pytest
from pathlib import Path
from unittest.mock import patch

from src.agent.prompt_manager import load_prompt, _resolve_includes, _interpolate, PROMPT_DIR


class TestInterpolation:
    def test_basic_variable(self):
        result = _interpolate("Hello {{name}}", {"name": "World"})
        assert result == "Hello World"

    def test_multiple_variables(self):
        result = _interpolate("{{a}} and {{b}}", {"a": "X", "b": "Y"})
        assert result == "X and Y"

    def test_missing_variable(self):
        result = _interpolate("{{missing}}", {})
        assert "MISSING:missing" in result

    def test_no_variables(self):
        result = _interpolate("No vars here", {"a": "1"})
        assert result == "No vars here"


class TestLoadPrompt:
    def test_load_recon_prompt(self):
        """Test that the recon prompt loads and resolves includes."""
        variables = {
            "device_count": "15",
            "link_count": "16",
            "cve_count": "24",
            "top_risk": "mikrotik",
            "previous_deliverables": "01_graph_analysis.md",
            "expected_deliverable": "02_recon.md",
            "target_subnet": "192.168.88.0/24",
            "scenario_context": "",
        }
        prompt = load_prompt("recon", variables)
        # Should contain content from @include(shared/_target.txt)
        assert "192.168.88.0/24" in prompt
        assert "15" in prompt
        assert "mikrotik" in prompt
        # Should have resolved the include
        assert "@include" not in prompt

    def test_load_graph_analysis_prompt(self):
        variables = {
            "device_count": "10",
            "link_count": "12",
            "cve_count": "5",
            "top_risk": "router",
            "previous_deliverables": "None",
            "expected_deliverable": "01_graph_analysis.md",
        }
        prompt = load_prompt("graph_analysis", variables)
        assert "topology" in prompt.lower()
        assert "@include" not in prompt

    def test_all_prompts_load(self):
        """Verify all 5 phase prompts load without error."""
        variables = {
            "device_count": "1",
            "link_count": "1",
            "cve_count": "0",
            "top_risk": "none",
            "previous_deliverables": "none",
            "expected_deliverable": "test.md",
        }
        for name in ["graph_analysis", "recon", "vuln_analysis", "exploitation", "report"]:
            prompt = load_prompt(name, variables)
            assert len(prompt) > 100
            assert "@include" not in prompt
