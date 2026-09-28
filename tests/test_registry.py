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
    def test_agent_definitions_reference_available_resources(self):
        valid_groups = {"graph", "recon", "deliverable", "skill", "intrusion"}
        for name, config in AGENTS.items():
            assert config.name == name
            assert isinstance(config.phase, int)
            assert config.prompt_template
            assert config.deliverable_file
            assert isinstance(config.tools, list)
            if name == "report":
                assert config.tools == []
            else:
                assert len(config.tools) > 0
            assert config.validator in VALIDATORS, (
                f"Agent {config.name} uses unknown validator '{config.validator}'"
            )
            for tool in config.tools:
                assert tool in valid_groups, (
                    f"Agent {config.name} uses unknown tool group '{tool}'"
                )

            for prereq in config.prerequisites:
                assert prereq in AGENTS, (
                    f"Agent {config.name} has unknown prerequisite '{prereq}'"
                )

    def test_registry_has_six_distinct_ordered_phases_and_outputs(self):
        assert set(AGENTS) == {
            "graph_analysis", "recon", "vuln_analysis", "exploitation", "intrusion", "report",
        }
        assert sorted(config.phase for config in AGENTS.values()) == [1, 2, 3, 4, 5, 6]
        outputs = [config.deliverable_file for config in AGENTS.values()]
        assert len(outputs) == len(set(outputs)), "Duplicate deliverable files"

    @pytest.mark.parametrize("name,expected", [
        pytest.param("exploitation", {"conditional": "03_vuln_analysis.json"}, id="verification-input"),
        pytest.param("intrusion", {
            "conditional": "04_exploitation.json", "validator": "json_intrusion",
            "prerequisites": ["exploitation"],
        }, id="intrusion-input-and-submission"),
        pytest.param("report", {
            "prerequisites": ["exploitation"], "phase": 6, "deliverable_file": "06_report.md",
        }, id="report-input-and-output"),
    ])
    def test_downstream_phase_contract(self, name, expected):
        config = AGENTS[name]
        assert {field: getattr(config, field) for field in expected} == expected
