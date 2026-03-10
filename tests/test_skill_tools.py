"""Tests for skill tools and knowledge search tools."""

from __future__ import annotations

import json

import pytest

from src.agent.tools.skill_tools import (
    list_skills,
    load_skill,
    SKILL_TOOLS,
    SKILLS_DIR,
)


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
        assert len(SKILL_TOOLS) == 4

    def test_all_have_required_fields(self):
        for tool in SKILL_TOOLS:
            assert "name" in tool
            assert "description" in tool
            assert "input_schema" in tool
            assert "function" in tool
            assert callable(tool["function"])

    def test_expected_tool_names(self):
        names = {t["name"] for t in SKILL_TOOLS}
        assert names == {"list_skills", "load_skill", "search_knowledge", "cve_search"}
