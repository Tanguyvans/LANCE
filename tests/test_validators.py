"""Tests for validators module."""
import json
from pathlib import Path

import pytest

from src.agent.validators import (
    validate_default,
    validate_final_report_markdown,
    validate_markdown_with_sections,
    validate_recon_markdown,
    validate_report_markdown,
    validate_json_device_vulns,
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

    def test_recon_rejects_short_single_device_report(self, clean_output):
        content = (
            "## 1. Summary\n| Metric | Value |\n|---|---|\n| Hosts | 1 |\n"
            "## 2. Discovered Services per Device\n"
            "| Device | IP | Open Ports | Key Services |\n|---|---|---|---|\n"
            "| router | 192.0.2.1 | 22 | ssh |\n"
            "## 3. Key Findings\nNone"
        )
        (clean_output / "recon.md").write_text(content)
        ok, msg = validate_recon_markdown("recon.md")
        assert not ok
        assert "rows" in msg or "short" in msg

    def test_report_rejects_missing_sections_and_placeholders(self, clean_output):
        (clean_output / "report.md").write_text("## 1. Executive Summary\nIncomplete")
        ok, msg = validate_report_markdown("report.md")
        assert not ok
        assert "sections" in msg

    def test_final_report_accepts_assembled_report_without_placeholders(self, clean_output):
        content = "# Pentest Report\n\n" + "\n\n".join(
            f"## {number}. Section {number}\n" + ("Evidence and analysis. " * 12)
            for number in range(1, 11)
        )
        (clean_output / "final.md").write_text(content)

        ok, msg = validate_final_report_markdown("final.md")

        assert ok, msg

    def test_final_report_rejects_unresolved_placeholders(self, clean_output):
        content = "# Pentest Report\n\n" + "\n\n".join(
            f"## {number}. Section {number}\n" + ("Evidence and analysis. " * 12)
            for number in range(1, 11)
        ) + "\n{{SECTION_5_TABLE}}\n"
        (clean_output / "final.md").write_text(content)

        ok, msg = validate_final_report_markdown("final.md")

        assert not ok
        assert "Unresolved" in msg

    def test_final_report_rejects_phase4_all_errors(self, clean_output):
        (clean_output / "04_exploitation.json").write_text(json.dumps({
            "summary": {
                "total_tested": 1,
                "confirmed": 0,
                "not_exploitable": 0,
                "errors": 1,
            },
            "tests": [{"vuln_id": "VULN-001", "status": "ERROR"}],
        }))
        content = "# Pentest Report\n\n" + "\n\n".join(
            f"## {number}. Section {number}\n" + ("Evidence and analysis. " * 12)
            for number in range(1, 11)
        )
        (clean_output / "final.md").write_text(content)

        ok, msg = validate_final_report_markdown("final.md")

        assert not ok
        assert "Phase 4" in msg


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
        data = {"vulnerabilities": [{
            "id": "VULN-001", "service": "http", "port": 80,
            "protocol": "tcp", "endpoint": "/", "product": "", "version": "",
        }], "summary": {"total": 1}}
        (clean_output / "good.json").write_text(json.dumps(data))
        ok, msg = validate_json_vuln_queue("good.json")
        assert ok


    def test_queue_rejects_missing_structural_fields(self, clean_output):
        data = {"vulnerabilities": [{"id": "VULN-001"}]}
        (clean_output / "missing-structure.json").write_text(json.dumps(data))
        ok, msg = validate_json_vuln_queue("missing-structure.json")
        assert not ok
        assert "structural fields" in msg

    def test_queue_rejects_duplicate_ids(self, clean_output):
        finding = {
            "id": "VULN-001", "service": "http", "port": 80,
            "protocol": "tcp", "endpoint": "/", "product": "", "version": "",
        }
        (clean_output / "duplicates.json").write_text(json.dumps({
            "vulnerabilities": [finding, dict(finding)],
        }))
        ok, msg = validate_json_vuln_queue("duplicates.json")
        assert not ok
        assert "Duplicate" in msg

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

    def test_exploitation_rejects_all_error_results(self, clean_output):
        data = {
            "summary": {
                "total_tested": 1,
                "confirmed": 0,
                "not_exploitable": 0,
                "errors": 1,
            },
            "tests": [{
                "vuln_id": "VULN-001",
                "status": "ERROR",
                "evidence": "No Phase 4 exploit result was produced",
            }],
        }
        (clean_output / "all-errors.json").write_text(json.dumps(data))

        ok, msg = validate_json_exploitation("all-errors.json")

        assert not ok
        assert "Missing per-vulnerability" in msg or "Phase 4" in msg


class TestValidateDeviceVulns:
    def test_requires_vulnerability_envelope(self, clean_output):
        (clean_output / "fragment.json").write_text(json.dumps({
            "id": "CVE-001", "type": "known_cve",
        }))
        ok, msg = validate_json_device_vulns("fragment.json")
        assert not ok
        assert "vulnerabilities" in msg

    def test_accepts_scanner_fallback_envelope(self, clean_output):
        (clean_output / "device.json").write_text(json.dumps({
            "device_id": "device-a",
            "vulnerabilities": [{"type": "missing_header"}],
        }))
        ok, msg = validate_json_device_vulns("device.json")
        assert ok


class TestValidatorsRegistry:
    def test_all_validators_callable(self):
        for name, fn in VALIDATORS.items():
            assert callable(fn)

    def test_expected_validators_exist(self):
        assert "default" in VALIDATORS
        assert "markdown_with_sections" in VALIDATORS
        assert "recon_markdown" in VALIDATORS
        assert "report_markdown" in VALIDATORS
        assert "final_report_markdown" in VALIDATORS
        assert "json_device_vulns" in VALIDATORS
        assert "json_vuln_queue" in VALIDATORS
        assert "json_exploitation" in VALIDATORS
        assert "json_valid" in VALIDATORS
