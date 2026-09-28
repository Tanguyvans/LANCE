"""Tests for deliverable tools module."""
import json

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
    @pytest.mark.parametrize("content", ["# Report\n## Section", "x" * 100],
                             ids=["markdown", "plain-text"])
    def test_save_preserves_content_and_reports_size(self, clean_output, content):
        result = json.loads(save_deliverable("test.md", content, output_dir=clean_output))
        assert result["status"] == "saved"
        assert (clean_output / "test.md").read_text() == content
        assert result["size"] == len(content)

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


class TestPrivateArtifactIsolation:
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

    @pytest.mark.parametrize("filename", ["provider_events.jsonl", "ground_truth.yaml"],
                             ids=["provider-diagnostics", "ground-truth"])
    @pytest.mark.parametrize("use_alias", [False, True], ids=["direct", "symlink"])
    def test_private_file_is_hidden_and_cannot_be_read_or_overwritten(
        self, clean_output, filename, use_alias
    ):
        private = clean_output / filename
        private.write_text("private-artifact-canary\n")
        before = private.read_bytes()
        requested = filename
        if use_alias:
            requested = "alias.md"
            (clean_output / requested).symlink_to(private)
        (clean_output / "report.md").write_text("report")

        read_result = read_deliverable(requested, output_dir=clean_output)
        save_result = save_deliverable(requested, "overwritten", output_dir=clean_output)

        assert json.loads(list_deliverables(output_dir=clean_output))["deliverables"] == ["report.md"]
        assert "error" in json.loads(read_result)
        assert "private-artifact-canary" not in read_result
        assert "error" in json.loads(save_result)
        assert private.read_bytes() == before

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

    def test_symlink_escape_cannot_be_read_or_overwritten(self, clean_output):
        outside = clean_output.parent / "outside-secret.txt"
        outside.write_text("secret-via-symlink")
        (clean_output / "link.txt").symlink_to(outside)

        read_result = read_deliverable("link.txt", output_dir=clean_output)
        save_result = save_deliverable("link.txt", "overwritten", output_dir=clean_output)

        assert "error" in json.loads(read_result)
        assert "secret-via-symlink" not in read_result
        assert "error" in json.loads(save_result)
        assert outside.read_text() == "secret-via-symlink"

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
    @pytest.mark.parametrize("filenames", [[], ["01_analysis.md", "02_recon.md"]],
                             ids=["empty", "multiple-files"])
    def test_lists_deliverables(self, clean_output, filenames):
        for filename in filenames:
            (clean_output / filename).write_text("content")
        result = json.loads(list_deliverables(output_dir=clean_output))
        assert result["deliverables"] == filenames


class TestAggregateDeviceResults:
    VULN = {"id": "VULN-001", "device_id": "s2-web", "type": "directory_listing", "severity": "HIGH"}

    def _write(self, path, content):
        path.write_text(content, encoding="utf-8")

    @pytest.mark.parametrize("device,prefix,vulnerabilities", [
        pytest.param("s2-web", "", [VULN], id="valid-json"),
        pytest.param("s2-mqtt", "json\n", [VULN], id="code-fence-prefix"),
        pytest.param("s2-db", "", [], id="empty-vulnerabilities"),
    ])
    def test_aggregates_device_json(self, clean_output, device, prefix, vulnerabilities):
        self._write(clean_output / f"03_device_{device}.json", prefix + json.dumps({
            "device_id": device, "vulnerabilities": vulnerabilities,
        }))
        result = json.loads(aggregate_device_results(output_dir=clean_output))
        assert result["vulnerabilities"] == vulnerabilities

    def test_malformed_prose_yields_error_entry(self, clean_output):
        # Case: LLM output pure prose (s2-iot-gw / s2-jump pattern)
        self._write(clean_output / "03_device_s2-jump.json",
                    "Based on my analysis the device has weak ciphers and PasswordAuthentication enabled.")
        result = json.loads(aggregate_device_results(output_dir=clean_output))
        assert len(result["vulnerabilities"]) == 1
        assert "error" in result["vulnerabilities"][0]
        assert "s2-jump" in result["vulnerabilities"][0]["error"]

    def test_multiple_devices_merged(self, clean_output):
        for device in ("s2-web", "s2-db"):
            self._write(clean_output / f"03_device_{device}.json", json.dumps({
                "device_id": device,
                "vulnerabilities": [{"id": "VULN-001", "device_id": device, "severity": "HIGH"}],
            }))
        result = json.loads(aggregate_device_results(output_dir=clean_output))
        assert len(result["vulnerabilities"]) == 2


class TestToolDefinitions:
    def test_expected_tools_have_required_fields(self):
        names = {t["name"] for t in DELIVERABLE_TOOLS}
        assert names == {"save_deliverable", "read_deliverable", "list_deliverables", "aggregate_device_results"}
        for tool in DELIVERABLE_TOOLS:
            assert "name" in tool
            assert "description" in tool
            assert "input_schema" in tool
            assert "function" in tool
            assert callable(tool["function"])
