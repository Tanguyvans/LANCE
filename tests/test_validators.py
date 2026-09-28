"""Tests for validators module."""
import json

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
)


@pytest.fixture(autouse=True)
def clean_output(tmp_path):
    """Pass each test's output directory explicitly."""
    return tmp_path


class TestValidateDefault:
    @pytest.mark.parametrize("content,expected,message", [
        pytest.param(None, False, "not found", id="missing-file"),
        pytest.param("", False, "empty", id="empty-file"),
        pytest.param("content", True, "", id="valid-file"),
    ])
    def test_file_content(self, clean_output, content, expected, message):
        if content is not None:
            (clean_output / "deliverable.md").write_text(content)
        ok, msg = validate_default("deliverable.md", output_dir=clean_output)
        assert ok is expected, msg
        assert message in msg


class TestValidateMarkdown:
    @pytest.mark.parametrize("content,expected,message", [
        pytest.param("No headings here", False, "0", id="no-headings"),
        pytest.param("## Only one\nContent", False, "", id="one-heading"),
        pytest.param("## Section 1\nText\n## Section 2\nMore text", True, "", id="two-headings"),
    ])
    def test_section_count(self, clean_output, content, expected, message):
        (clean_output / "sections.md").write_text(content)
        ok, msg = validate_markdown_with_sections("sections.md", output_dir=clean_output)
        assert ok is expected, msg
        assert message in msg

    def test_recon_rejects_short_single_device_report(self, clean_output):
        content = (
            "## 1. Summary\n| Metric | Value |\n|---|---|\n| Hosts | 1 |\n"
            "## 2. Discovered Services per Device\n"
            "| Device | IP | Open Ports | Key Services |\n|---|---|---|---|\n"
            "| router | 192.0.2.1 | 22 | ssh |\n"
            "## 3. Key Findings\nNone"
        )
        (clean_output / "recon.md").write_text(content)
        ok, msg = validate_recon_markdown("recon.md", output_dir=clean_output)
        assert not ok
        assert "rows" in msg or "short" in msg

    def test_report_rejects_missing_sections_and_placeholders(self, clean_output):
        (clean_output / "report.md").write_text("## 1. Executive Summary\nIncomplete")
        ok, msg = validate_report_markdown("report.md", output_dir=clean_output)
        assert not ok
        assert "sections" in msg

    @pytest.mark.parametrize("suffix,phase4,expected,message", [
        pytest.param("", None, True, "", id="assembled-report"),
        pytest.param("\n{{SECTION_5_TABLE}}\n", None, False, "Unresolved", id="unresolved-placeholder"),
        pytest.param("", {
            "summary": {"total_tested": 1, "confirmed": 0, "not_exploitable": 0, "errors": 1},
            "tests": [{"vuln_id": "VULN-001", "status": "ERROR"}],
        }, False, "Phase 4", id="all-phase4-results-are-errors"),
    ])
    def test_final_report(self, clean_output, suffix, phase4, expected, message):
        if phase4 is not None:
            (clean_output / "04_exploitation.json").write_text(json.dumps(phase4))
        content = "# Pentest Report\n\n" + "\n\n".join(
            f"## {number}. Section {number}\n" + ("Evidence and analysis. " * 12)
            for number in range(1, 11)
        ) + suffix
        (clean_output / "final.md").write_text(content)
        ok, msg = validate_final_report_markdown("final.md", output_dir=clean_output)
        assert ok is expected, msg
        assert message in msg


class TestValidateJsonQueue:
    FINDING = {
        "id": "VULN-001", "service": "http", "port": 80,
        "protocol": "tcp", "endpoint": "/", "product": "", "version": "",
    }

    @pytest.mark.parametrize("content,expected,message", [
        pytest.param("not json", False, "Invalid JSON", id="invalid-json"),
        pytest.param('{"other": []}', False, "vulnerabilities", id="missing-key"),
        pytest.param(json.dumps({"vulnerabilities": [FINDING], "summary": {"total": 1}}),
                     True, "", id="valid-queue"),
        pytest.param('{"vulnerabilities": [{"id": "VULN-001"}]}',
                     False, "structural fields", id="missing-structural-fields"),
        pytest.param(json.dumps({"vulnerabilities": [FINDING, dict(FINDING)]}),
                     False, "Duplicate", id="duplicate-ids"),
        pytest.param('{"vulnerabilities": []}', True, "", id="empty-queue"),
    ])
    def test_queue_validation(self, clean_output, content, expected, message):
        (clean_output / "queue.json").write_text(content)
        ok, msg = validate_json_vuln_queue("queue.json", output_dir=clean_output)
        assert ok is expected, msg
        assert message in msg


class TestValidateJsonExploitation:
    @pytest.mark.parametrize("content,expected,messages", [
        pytest.param("not json", False, ("Invalid JSON",), id="invalid-json"),
        pytest.param('{"other": []}', False, ("tests",), id="missing-tests-key"),
        pytest.param('{"tests": "string"}', False, ("array",), id="tests-not-array"),
        pytest.param(json.dumps({
            "summary": {"total_tested": 1, "confirmed": 1},
            "tests": [{"vuln_id": "VULN-001", "status": "CONFIRMED"}],
        }), True, ("",), id="confirmed-result"),
        pytest.param(json.dumps({
            "summary": {"total_tested": 1, "confirmed": 1, "not_exploitable": 0, "errors": 0},
            "tests": [
                {"vuln_id": "VULN-001", "status": "CONFIRMED"},
                {
                    "vuln_id": "VULN-002", "status": "SKIPPED",
                    "evidence": "Skipped Phase 4 exploit agent: configuration_or_detection_only",
                },
            ],
        }), True, ("",), id="skipped-unscheduled-finding"),
        pytest.param(json.dumps({
            "summary": {"total_tested": 1, "confirmed": 0, "not_exploitable": 0, "errors": 1},
            "tests": [{
                "vuln_id": "VULN-001", "status": "ERROR",
                "evidence": "No Phase 4 exploit result was produced",
            }],
        }), False, ("Missing per-vulnerability", "Phase 4"), id="all-error-results"),
    ])
    def test_exploitation_validation(self, clean_output, content, expected, messages):
        (clean_output / "exploitation.json").write_text(content)
        ok, msg = validate_json_exploitation("exploitation.json", output_dir=clean_output)
        assert ok is expected, msg
        assert any(message in msg for message in messages), msg


class TestValidateDeviceVulns:
    @pytest.mark.parametrize("data,expected,message", [
        pytest.param({"id": "CVE-001", "type": "known_cve"},
                     False, "vulnerabilities", id="missing-envelope"),
        pytest.param({"device_id": "device-a", "vulnerabilities": [{"type": "missing_header"}]},
                     True, "", id="scanner-fallback-envelope"),
    ])
    def test_vulnerability_envelope(self, clean_output, data, expected, message):
        (clean_output / "device.json").write_text(json.dumps(data))
        ok, msg = validate_json_device_vulns("device.json", output_dir=clean_output)
        assert ok is expected, msg
        assert message in msg


class TestValidatorsRegistry:
    def test_expected_validators_are_available_and_callable(self):
        assert {
            "default", "markdown_with_sections", "recon_markdown", "report_markdown",
            "final_report_markdown", "json_device_vulns", "json_vuln_queue",
            "json_exploitation", "json_valid",
        } <= VALIDATORS.keys()
        for name, fn in VALIDATORS.items():
            assert callable(fn), name
