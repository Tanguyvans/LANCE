import pytest

from src.agent.artifacts import artifact_available


@pytest.mark.parametrize("content,available", [("", False), ("broken", False), ("null", False), ('{"tests": []}', True)])
def test_json_availability(tmp_path, content, available):
    (tmp_path / "result.json").write_text(content)
    assert artifact_available(tmp_path, "result.json") is available


def test_missing_directory_and_external_paths_are_unavailable(tmp_path):
    assert not artifact_available(tmp_path, "missing.md")
    assert not artifact_available(tmp_path, ".")
    assert not artifact_available(tmp_path, "../outside.md")
    assert not artifact_available(tmp_path, str(tmp_path / "result.md"))


def test_symlink_cannot_reuse_external_artifact(tmp_path):
    root = tmp_path / "run"
    root.mkdir()
    outside = tmp_path / "external.md"
    outside.write_text("content")
    (root / "result.md").symlink_to(outside)
    assert not artifact_available(root, "result.md")
