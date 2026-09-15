"""Tests for deliverable tools module."""
import json
from pathlib import Path

import pytest

from src.agent.tools.deliverable import (
    save_deliverable,
    read_deliverable,
    list_deliverables,
    aggregate_device_results,
    DELIVERABLE_TOOLS,
)


@pytest.fixture(autouse=True)
def clean_output(tmp_path):
    """Pass each test's output directory explicitly."""
    return tmp_path


class TestSaveDeliverable:
    def test_save_creates_file(self, clean_output):
        result = json.loads(save_deliverable("test.md", "# Report\n## Section", output_dir=clean_output))
        assert result["status"] == "saved"
        assert (clean_output / "test.md").exists()
        assert (clean_output / "test.md").read_text() == "# Report\n## Section"

    def test_save_returns_size(self, clean_output):
        content = "x" * 100
        result = json.loads(save_deliverable("big.md", content, output_dir=clean_output))
        assert result["size"] == 100

    def test_save_rejects_empty_content(self, clean_output):
        result = json.loads(save_deliverable("empty.md", "  \n", output_dir=clean_output))
        assert result["ok"] is False
        assert result["error_kind"] == "empty_deliverable"
        assert not (clean_output / "empty.md").exists()


class TestReadDeliverable:
    def test_read_existing(self, clean_output):
        (clean_output / "test.md").write_text("hello")
        result = json.loads(read_deliverable("test.md", output_dir=clean_output))
        assert result["content"] == "hello"
        assert result["filename"] == "test.md"

    def test_read_missing(self, clean_output):
        result = json.loads(read_deliverable("nonexistent.md", output_dir=clean_output))
        assert "error" in result


class TestProviderDiagnosticIsolation:
    def test_unrelated_cwd_alias_does_not_hide_a_run_deliverable(self, clean_output, monkeypatch):
        (clean_output / "report.md").write_text("run report")
        other = clean_output / "unrelated-cwd"
        other.mkdir()
        (other / "provider_events.jsonl").write_text("private")
        (other / "report.md").symlink_to(other / "provider_events.jsonl")
        monkeypatch.chdir(other)

        assert json.loads(read_deliverable("report.md", output_dir=clean_output))["content"] == "run report"
        assert json.loads(save_deliverable("report.md", "updated", output_dir=clean_output))["status"] == "saved"
        assert (clean_output / "report.md").read_text() == "updated"
        assert (other / "provider_events.jsonl").read_text() == "private"

    def test_observer_file_is_hidden_and_cannot_be_overwritten(self, clean_output):
        journal = clean_output / "provider_events.jsonl"
        journal.write_text('{"event":"terminal","reason":"test-canary"}\n')
        before = journal.read_bytes()
        (clean_output / "report.md").write_text("report")
        assert json.loads(list_deliverables(output_dir=clean_output))["deliverables"] == ["report.md"]
        assert "error" in json.loads(read_deliverable(journal.name, output_dir=clean_output))
        assert "error" in json.loads(save_deliverable(journal.name, "overwritten", output_dir=clean_output))
        assert journal.read_bytes() == before

    def test_alias_cannot_expose_diagnostic_file(self, clean_output):
        journal = clean_output / "provider_events.jsonl"
        journal.write_text("private-observer-canary")
        (clean_output / "alias.md").symlink_to(journal)
        result = read_deliverable("alias.md", output_dir=clean_output)
        assert "error" in json.loads(result)
        assert "private-observer-canary" not in result
        assert "error" in json.loads(save_deliverable("alias.md", "changed", output_dir=clean_output))
        assert json.loads(list_deliverables(output_dir=clean_output))["deliverables"] == []

    def test_ground_truth_alias_cannot_be_read_or_overwritten(self, clean_output):
        ground_truth = clean_output / "ground_truth.yaml"
        ground_truth.write_text("answer-key")
        (clean_output / "ground-truth-alias.md").symlink_to(ground_truth)

        assert "error" in json.loads(read_deliverable("ground-truth-alias.md", output_dir=clean_output))
        assert "error" in json.loads(save_deliverable("ground-truth-alias.md", "changed", output_dir=clean_output))
        assert json.loads(list_deliverables(output_dir=clean_output))["deliverables"] == []
        assert ground_truth.read_text() == "answer-key"

    def test_reserved_name_cannot_redirect_writes(self, clean_output):
        target = clean_output / "report.md"
        target.write_text("untouched")
        (clean_output / "provider_events.jsonl").symlink_to(target)
        assert "error" in json.loads(save_deliverable("provider_events.jsonl", "changed", output_dir=clean_output))
        assert target.read_text() == "untouched"


class TestDeliverablePathConfinement:
    def test_read_rejects_parent_traversal(self, clean_output):
        outside = clean_output.parent / "secret.txt"
        outside.write_text("oracle-secret")

        result = json.loads(read_deliverable("../secret.txt", output_dir=clean_output))

        assert "error" in result
        assert "oracle-secret" not in json.dumps(result)

    def test_save_rejects_parent_traversal(self, clean_output):
        outside = clean_output.parent / "escaped.txt"

        result = json.loads(save_deliverable("../escaped.txt", "should-not-exist", output_dir=clean_output))

        assert "error" in result
        assert not outside.exists()

    def test_absolute_paths_are_rejected(self, clean_output):
        target = clean_output / "absolute.md"

        read_result = json.loads(read_deliverable(str(target), output_dir=clean_output))
        save_result = json.loads(save_deliverable(str(target), "content", output_dir=clean_output))

        assert "error" in read_result
        assert "error" in save_result
        assert not target.exists()

    def test_read_rejects_symlink_escape(self, clean_output):
        outside = clean_output.parent / "outside-secret.txt"
        outside.write_text("secret-via-symlink")
        (clean_output / "link.txt").symlink_to(outside)

        result = json.loads(read_deliverable("link.txt", output_dir=clean_output))

        assert "error" in result
        assert "secret-via-symlink" not in json.dumps(result)

    def test_save_rejects_symlink_escape(self, clean_output):
        outside = clean_output.parent / "outside-target.txt"
        outside.write_text("original")
        (clean_output / "link.txt").symlink_to(outside)

        result = json.loads(save_deliverable("link.txt", "overwritten", output_dir=clean_output))

        assert "error" in result
        assert outside.read_text() == "original"

    def test_hidden_ground_truth_cannot_be_read_or_overwritten(self, clean_output):
        hidden = clean_output / "ground_truth.yaml"
        hidden.write_text("answer-key")

        read_result = json.loads(read_deliverable("ground_truth.yaml", output_dir=clean_output))
        save_result = json.loads(save_deliverable("ground_truth.yaml", "tampered", output_dir=clean_output))

        assert "error" in read_result
        assert "error" in save_result
        assert hidden.read_text() == "answer-key"

    def test_list_omits_hidden_and_escaping_symlink(self, clean_output):
        (clean_output / "visible.md").write_text("ok")
        (clean_output / "ground_truth.yaml").write_text("answer-key")
        outside = clean_output.parent / "outside-list.txt"
        outside.write_text("secret")
        (clean_output / "outside-link.txt").symlink_to(outside)

        result = json.loads(list_deliverables(output_dir=clean_output))

        assert result["deliverables"] == ["visible.md"]

    def test_aggregate_rejects_path_pattern(self, clean_output):
        result = json.loads(aggregate_device_results("../*.json", output_dir=clean_output))

        assert result["vulnerabilities"] == []
        assert "error" in result


class TestListDeliverables:
    def test_empty_dir(self, clean_output):
        result = json.loads(list_deliverables(output_dir=clean_output))
        assert result["deliverables"] == []

    def test_with_files(self, clean_output):
        (clean_output / "01_analysis.md").write_text("a")
        (clean_output / "02_recon.md").write_text("b")
        result = json.loads(list_deliverables(output_dir=clean_output))
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
        result = json.loads(aggregate_device_results(output_dir=clean_output))
        assert len(result["vulnerabilities"]) == 1
        assert result["vulnerabilities"][0]["id"] == "VULN-001"

    def test_malformed_prose_yields_error_entry(self, clean_output):
        # Case: LLM output pure prose (s2-iot-gw / s2-jump pattern)
        self._write(clean_output / "03_device_s2-jump.json",
                    "Based on my analysis the device has weak ciphers and PasswordAuthentication enabled.")
        result = json.loads(aggregate_device_results(output_dir=clean_output))
        assert len(result["vulnerabilities"]) == 1
        assert "error" in result["vulnerabilities"][0]
        assert "s2-jump" in result["vulnerabilities"][0]["error"]

    def test_code_fence_prefix_parsed_by_aggregate(self, clean_output):
        # aggregate_device_results must recover JSON even if file starts with "json\n{...}"
        raw = 'json\n{"device_id": "s2-mqtt", "vulnerabilities": [' + json.dumps(self.VULN) + ']}'
        self._write(clean_output / "03_device_s2-mqtt.json", raw)
        result = json.loads(aggregate_device_results(output_dir=clean_output))
        assert len(result["vulnerabilities"]) == 1
        assert result["vulnerabilities"][0]["type"] == self.VULN["type"]

    def test_multiple_devices_merged(self, clean_output):
        for device in ("s2-web", "s2-db"):
            self._write(clean_output / f"03_device_{device}.json", json.dumps({
                "device_id": device,
                "vulnerabilities": [{"id": "VULN-001", "device_id": device, "severity": "HIGH"}],
            }))
        result = json.loads(aggregate_device_results(output_dir=clean_output))
        assert len(result["vulnerabilities"]) == 2

    def test_empty_vulns_device_skipped_silently(self, clean_output):
        self._write(clean_output / "03_device_s2-db.json", json.dumps({
            "device_id": "s2-db",
            "vulnerabilities": [],
        }))
        result = json.loads(aggregate_device_results(output_dir=clean_output))
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
