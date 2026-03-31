"""Tests for agent registry module."""
import pytest

from src.agent.registry import AGENTS, AgentConfig
from src.agent.validators import VALIDATORS


class TestAgentConfig:
    def test_dataclass_fields(self):
        config = AgentConfig(
            name="test",
            phase=1,
            prompt_template="test",
            deliverable_file="test.md",
            tools=["graph"],
        )
        assert config.name == "test"
        assert config.phase == 1
        assert config.validator == "default"
        assert config.max_turns == 30
        assert config.conditional is None
        assert config.prerequisites == []


class TestAgentsRegistry:
    def test_all_agents_have_required_fields(self):
        for name, config in AGENTS.items():
            assert config.name == name
            assert isinstance(config.phase, int)
            assert config.prompt_template
            assert config.deliverable_file
            assert isinstance(config.tools, list)
            assert len(config.tools) > 0

    def test_unique_phases(self):
        phases = [a.phase for a in AGENTS.values()]
        assert len(phases) == len(set(phases)), "Duplicate phase numbers"

    def test_unique_deliverables(self):
        deliverables = [a.deliverable_file for a in AGENTS.values()]
        assert len(deliverables) == len(set(deliverables)), "Duplicate deliverable files"

    def test_five_agents(self):
        assert len(AGENTS) == 5

    def test_expected_agent_names(self):
        expected = {"graph_analysis", "recon", "vuln_analysis", "exploitation", "report"}
        assert set(AGENTS.keys()) == expected

    def test_phases_sequential(self):
        phases = sorted(a.phase for a in AGENTS.values())
        assert phases == [1, 2, 3, 4, 5]

    def test_validators_exist(self):
        for config in AGENTS.values():
            assert config.validator in VALIDATORS, (
                f"Agent {config.name} uses unknown validator '{config.validator}'"
            )

    def test_tool_groups_valid(self):
        valid_groups = {"graph", "recon", "deliverable", "skill"}
        for config in AGENTS.values():
            for tool in config.tools:
                assert tool in valid_groups, (
                    f"Agent {config.name} uses unknown tool group '{tool}'"
                )

    def test_prerequisites_reference_existing_agents(self):
        for config in AGENTS.values():
            for prereq in config.prerequisites:
                assert prereq in AGENTS, (
                    f"Agent {config.name} has unknown prerequisite '{prereq}'"
                )

    def test_exploitation_has_conditional(self):
        assert AGENTS["exploitation"].conditional == "03_vuln_analysis.json"

    def test_report_prerequisites(self):
        assert AGENTS["report"].prerequisites == ["exploitation"]
