"""Tests for skill tools and knowledge search tools."""

from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

import pytest

import src.agent.knowledge.store  # noqa: F401 — registers module so @patch("src.agent.knowledge.store.search") works
from src.agent.tools.skill_tools import (
    list_skills,
    load_skill,
    search_history,
    set_skill_filter,
    SKILL_TOOLS,
    SKILLS_DIR,
)


@pytest.fixture(autouse=True)
def clear_skill_filter():
    """Ensure no skill filter is active between tests."""
    set_skill_filter(None)
    yield
    set_skill_filter(None)


class TestListSkills:
    """Test skill discovery."""

    def test_returns_all_skills(self):
        result = json.loads(list_skills())
        names = {s["name"] for s in result}
        assert "mqtt_security" in names
        assert "ssh_hardening" in names
        assert "lorawan_analysis" in names
        assert "mikrotik_routeros" in names
        assert "web_service_analysis" in names
        assert "firmware_analysis" in names
        assert "zigbee_security" in names
        assert "report_methodology" in names

    def test_skills_have_description(self):
        result = json.loads(list_skills())
        for skill in result:
            assert skill["description"], f"Skill {skill['name']} has no description"

    def test_skills_have_tags(self):
        result = json.loads(list_skills())
        for skill in result:
            assert isinstance(skill["tags"], list)
            assert len(skill["tags"]) > 0, f"Skill {skill['name']} has no tags"

    def test_skills_have_tools(self):
        result = json.loads(list_skills())
        for skill in result:
            assert isinstance(skill["tools"], list)
            assert len(skill["tools"]) > 0, f"Skill {skill['name']} has no tools"

    def test_returns_json(self):
        result = list_skills()
        parsed = json.loads(result)
        assert isinstance(parsed, list)


class TestLoadSkill:
    """Test skill loading."""

    def test_load_existing_skill(self):
        result = json.loads(load_skill("mqtt_security"))
        assert result["skill"] == "mqtt_security"
        assert "MQTT" in result["content"]
        assert "## Methodology" in result["content"]
        assert "meta" in result
        assert result["meta"]["name"] == "mqtt_security"
        assert "mqtt" in result["meta"]["tags"]

    def test_load_missing_skill(self):
        result = json.loads(load_skill("nonexistent_skill"))
        assert "error" in result
        assert "available" in result
        assert "mqtt_security" in result["available"]

    def test_each_skill_has_required_sections(self):
        required_sections = ["## Overview", "## Methodology", "## Tools & Commands"]
        result = json.loads(list_skills())
        for skill_info in result:
            content = json.loads(load_skill(skill_info["name"]))["content"]
            for section in required_sections:
                assert section in content, (
                    f"Skill {skill_info['name']} missing section: {section}"
                )


class TestSkillToolDefinitions:
    """Test that SKILL_TOOLS are properly formatted."""

    def test_tool_count(self):
        assert len(SKILL_TOOLS) == 6

    def test_all_have_required_fields(self):
        for tool in SKILL_TOOLS:
            assert "name" in tool
            assert "description" in tool
            assert "input_schema" in tool
            assert "function" in tool
            assert callable(tool["function"])

    def test_expected_tool_names(self):
        names = {t["name"] for t in SKILL_TOOLS}
        assert names == {"list_skills", "load_skill", "search_knowledge", "cve_search", "search_history"}


class TestSearchHistory:
    """Test run history search."""

    @patch("src.agent.knowledge.store.search")
    def test_search_returns_results(self, mock_search):
        mock_search.return_value = [
            {"id": "run_1_VULN-001", "document": "MQTT no auth", "similarity": 0.9}
        ]
        result = json.loads(search_history("MQTT anonymous"))
        assert isinstance(result, list)
        assert len(result) == 1
        mock_search.assert_called_once_with("run_history", "MQTT anonymous", top_k=5, where=None)

    @patch("src.agent.knowledge.store.search")
    def test_search_with_device_filter(self, mock_search):
        mock_search.return_value = []
        search_history("SSH weak cipher", device_id="mikrotik", top_k=3)
        mock_search.assert_called_once_with(
            "run_history", "SSH weak cipher", top_k=3, where={"device_id": "mikrotik"}
        )

    @patch("src.agent.knowledge.store.search", side_effect=Exception("DB unavailable"))
    def test_search_handles_error(self, mock_search):
        result = json.loads(search_history("test query"))
        assert "error" in result


class TestHardFiltering:
    """Test that skill filter restricts list_skills and load_skill."""

    def test_no_filter_returns_all(self):
        set_skill_filter(None)
        result = json.loads(list_skills())
        assert len(result) == 8

    def test_filter_by_mqtt_tag(self):
        set_skill_filter(["mqtt"])
        result = json.loads(list_skills())
        names = {s["name"] for s in result}
        assert "mqtt_security" in names
        assert "ssh_hardening" not in names
        assert "report_methodology" not in names

    def test_filter_by_report_tag(self):
        set_skill_filter(["report", "methodology"])
        result = json.loads(list_skills())
        names = {s["name"] for s in result}
        assert names == {"report_methodology"}

    def test_load_skill_blocked_by_filter(self):
        set_skill_filter(["mqtt"])
        result = json.loads(load_skill("ssh_hardening"))
        assert "error" in result
        assert "not available for this phase" in result["error"]
        assert "mqtt_security" in result["available"]
        assert "ssh_hardening" not in result["available"]

    def test_load_skill_allowed_by_filter(self):
        set_skill_filter(["mqtt"])
        result = json.loads(load_skill("mqtt_security"))
        assert "skill" in result
        assert result["skill"] == "mqtt_security"

    def test_load_missing_skill_shows_filtered_available(self):
        set_skill_filter(["mqtt"])
        result = json.loads(load_skill("nonexistent_skill"))
        assert "error" in result
        # Available list should only show filtered skills
        assert "mqtt_security" in result["available"]
        assert "ssh_hardening" not in result["available"]
