"""Tests for validators module."""
import json
from pathlib import Path

import pytest

from src.agent.validators import (
    validate_default,
    validate_markdown_with_sections,
    validate_json_vuln_queue,
    validate_json_exploitation,
    VALIDATORS,
    OUTPUT_DIR,
)


@pytest.fixture(autouse=True)
def clean_output(tmp_path, monkeypatch):
    """Use a temp directory for output/agent."""
    import src.agent.validators as mod
    monkeypatch.setattr(mod, "OUTPUT_DIR", tmp_path)
    return tmp_path


class TestValidateDefault:
    def test_missing_file(self, clean_output):
        ok, msg = validate_default("nonexistent.md")
        assert not ok
        assert "not found" in msg

    def test_empty_file(self, clean_output):
        (clean_output / "empty.md").write_text("")
        ok, msg = validate_default("empty.md")
        assert not ok
        assert "empty" in msg

    def test_valid_file(self, clean_output):
        (clean_output / "valid.md").write_text("content")
        ok, msg = validate_default("valid.md")
        assert ok


class TestValidateMarkdown:
    def test_no_headings(self, clean_output):
        (clean_output / "bad.md").write_text("No headings here")
        ok, msg = validate_markdown_with_sections("bad.md")
        assert not ok
        assert "0" in msg

    def test_one_heading(self, clean_output):
        (clean_output / "one.md").write_text("## Only one\nContent")
        ok, msg = validate_markdown_with_sections("one.md")
        assert not ok

    def test_valid_markdown(self, clean_output):
        content = "## Section 1\nText\n## Section 2\nMore text"
        (clean_output / "good.md").write_text(content)
        ok, msg = validate_markdown_with_sections("good.md")
        assert ok


class TestValidateJsonQueue:
    def test_invalid_json(self, clean_output):
        (clean_output / "bad.json").write_text("not json")
        ok, msg = validate_json_vuln_queue("bad.json")
        assert not ok
        assert "Invalid JSON" in msg

    def test_missing_key(self, clean_output):
        (clean_output / "nokey.json").write_text('{"other": []}')
        ok, msg = validate_json_vuln_queue("nokey.json")
        assert not ok
        assert "vulnerabilities" in msg

    def test_valid_queue(self, clean_output):
        data = {"vulnerabilities": [{"id": "VULN-001"}], "summary": {"total": 1}}
        (clean_output / "good.json").write_text(json.dumps(data))
        ok, msg = validate_json_vuln_queue("good.json")
        assert ok

    def test_empty_queue(self, clean_output):
        data = {"vulnerabilities": []}
        (clean_output / "empty.json").write_text(json.dumps(data))
        ok, msg = validate_json_vuln_queue("empty.json")
        assert ok  # Valid structure, just empty


class TestValidateJsonExploitation:
    def test_invalid_json(self, clean_output):
        (clean_output / "bad.json").write_text("not json")
        ok, msg = validate_json_exploitation("bad.json")
        assert not ok
        assert "Invalid JSON" in msg

    def test_missing_tests_key(self, clean_output):
        (clean_output / "nokey.json").write_text('{"other": []}')
        ok, msg = validate_json_exploitation("nokey.json")
        assert not ok
        assert "tests" in msg

    def test_tests_not_array(self, clean_output):
        (clean_output / "notarray.json").write_text('{"tests": "string"}')
        ok, msg = validate_json_exploitation("notarray.json")
        assert not ok
        assert "array" in msg

    def test_valid_exploitation(self, clean_output):
        data = {
            "summary": {"total_tested": 1, "confirmed": 1},
            "tests": [{"vuln_id": "VULN-001", "status": "CONFIRMED"}],
        }
        (clean_output / "good.json").write_text(json.dumps(data))
        ok, msg = validate_json_exploitation("good.json")
        assert ok


class TestValidatorsRegistry:
    def test_all_validators_callable(self):
        for name, fn in VALIDATORS.items():
            assert callable(fn)

    def test_expected_validators_exist(self):
        assert "default" in VALIDATORS
        assert "markdown_with_sections" in VALIDATORS
        assert "json_vuln_queue" in VALIDATORS
        assert "json_exploitation" in VALIDATORS
        assert "json_valid" in VALIDATORS
