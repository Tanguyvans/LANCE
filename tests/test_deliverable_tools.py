"""Tests for deliverable tools module."""
import json
from pathlib import Path

import pytest

from src.agent.tools.deliverable import (
    save_deliverable,
    read_deliverable,
    list_deliverables,
    aggregate_device_results,
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


class TestAggregateDeviceResults:
    VULN = {"id": "VULN-001", "device_id": "s2-web", "type": "directory_listing", "severity": "HIGH"}

    def _write(self, path, content):
        path.write_text(content, encoding="utf-8")

    def test_aggregates_valid_json(self, clean_output):
        self._write(clean_output / "03_device_s2-web.json", json.dumps({
            "device_id": "s2-web",
            "vulnerabilities": [self.VULN],
        }))
        result = json.loads(aggregate_device_results())
        assert len(result["vulnerabilities"]) == 1
        assert result["vulnerabilities"][0]["id"] == "VULN-001"

    def test_malformed_prose_yields_error_entry(self, clean_output):
        # Case: LLM output pure prose (s2-iot-gw / s2-jump pattern)
        self._write(clean_output / "03_device_s2-jump.json",
                    "Based on my analysis the device has weak ciphers and PasswordAuthentication enabled.")
        result = json.loads(aggregate_device_results())
        assert len(result["vulnerabilities"]) == 1
        assert "error" in result["vulnerabilities"][0]
        assert "s2-jump" in result["vulnerabilities"][0]["error"]

    def test_code_fence_prefix_yields_error_before_fix(self, clean_output):
        # Reproduces the s2-mqtt bug: file starts with "json\n{...}" (raw fallback without strip)
        raw = 'json\n{"device_id": "s2-mqtt", "vulnerabilities": [' + json.dumps(self.VULN) + ']}'
        self._write(clean_output / "03_device_s2-mqtt.json", raw)
        result = json.loads(aggregate_device_results())
        # Without stripping, "json\n{..." is not valid JSON → error entry
        assert "error" in result["vulnerabilities"][0]

    def test_multiple_devices_merged(self, clean_output):
        for device in ("s2-web", "s2-db"):
            self._write(clean_output / f"03_device_{device}.json", json.dumps({
                "device_id": device,
                "vulnerabilities": [{"id": "VULN-001", "device_id": device, "severity": "HIGH"}],
            }))
        result = json.loads(aggregate_device_results())
        assert len(result["vulnerabilities"]) == 2

    def test_empty_vulns_device_skipped_silently(self, clean_output):
        self._write(clean_output / "03_device_s2-db.json", json.dumps({
            "device_id": "s2-db",
            "vulnerabilities": [],
        }))
        result = json.loads(aggregate_device_results())
        assert result["vulnerabilities"] == []


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
        assert names == {"save_deliverable", "read_deliverable", "list_deliverables", "aggregate_device_results"}
