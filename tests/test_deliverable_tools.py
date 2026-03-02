"""Tests for deliverable tools module."""
import json
from pathlib import Path

import pytest

from src.agent.tools.deliverable import (
    save_deliverable,
    read_deliverable,
    list_deliverables,
    set_output_dir,
    DELIVERABLE_TOOLS,
)


@pytest.fixture(autouse=True)
def clean_output(tmp_path, monkeypatch):
    """Use a temp directory for output/agent."""
    import src.agent.tools.deliverable as mod
    monkeypatch.setattr(mod, "OUTPUT_DIR", tmp_path)
    return tmp_path


class TestSaveDeliverable:
    def test_save_creates_file(self, clean_output):
        result = json.loads(save_deliverable("test.md", "# Report\n## Section"))
        assert result["status"] == "saved"
        assert (clean_output / "test.md").exists()
        assert (clean_output / "test.md").read_text() == "# Report\n## Section"

    def test_save_returns_size(self, clean_output):
        content = "x" * 100
        result = json.loads(save_deliverable("big.md", content))
        assert result["size"] == 100


class TestReadDeliverable:
    def test_read_existing(self, clean_output):
        (clean_output / "test.md").write_text("hello")
        result = json.loads(read_deliverable("test.md"))
        assert result["content"] == "hello"
        assert result["filename"] == "test.md"

    def test_read_missing(self, clean_output):
        result = json.loads(read_deliverable("nonexistent.md"))
        assert "error" in result


class TestListDeliverables:
    def test_empty_dir(self, clean_output):
        result = json.loads(list_deliverables())
        assert result["deliverables"] == []

    def test_with_files(self, clean_output):
        (clean_output / "01_analysis.md").write_text("a")
        (clean_output / "02_recon.md").write_text("b")
        result = json.loads(list_deliverables())
        assert len(result["deliverables"]) == 2
        assert "01_analysis.md" in result["deliverables"]


class TestToolDefinitions:
    def test_all_tools_have_required_fields(self):
        for tool in DELIVERABLE_TOOLS:
            assert "name" in tool
            assert "description" in tool
            assert "input_schema" in tool
            assert "function" in tool
            assert callable(tool["function"])

    def test_tool_names(self):
        names = {t["name"] for t in DELIVERABLE_TOOLS}
        assert names == {"save_deliverable", "read_deliverable", "list_deliverables"}
