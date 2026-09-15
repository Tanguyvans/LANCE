"""Keep the renamed training tree, synchronization and test discovery aligned."""
from configparser import ConfigParser
from pathlib import Path

import yaml

from scripts.training_workspace import DEFAULT_MANIFEST, build_push_plan, load_manifest


ROOT = Path(__file__).resolve().parents[2]


def test_default_manifest_uses_model_training_and_all_sources_exist(tmp_path):
    assert DEFAULT_MANIFEST == ROOT / "model_training" / "workspace_sync.json"
    manifest = load_manifest(DEFAULT_MANIFEST)
    plan = build_push_plan(ROOT, tmp_path, manifest)
    assert plan
    assert all(item.relative_path.parts[0] == "model_training" for item in plan)
    assert all(item.source.is_file() for item in plan)
    assert all(item.destination.is_relative_to(tmp_path) for item in plan)


def test_chat_template_resolves_inside_renamed_tree():
    config = yaml.safe_load((ROOT / "model_training/configs/qlora_qwen2_5_3b.yaml").read_text())
    template = config["data"]["chat_template_path"]
    assert Path(template).parts[0] == "model_training"
    assert (ROOT / template).is_file()


def test_default_pytest_discovery_includes_both_test_roots():
    config = ConfigParser()
    config.read(ROOT / "pytest.ini")
    assert set(config["pytest"]["testpaths"].split()) == {"tests", "model_training/tests"}


def test_ci_runs_both_test_roots():
    workflow = yaml.load(
        (ROOT / ".github/workflows/benchmark-integrity.yml").read_text(),
        Loader=yaml.BaseLoader,
    )
    step = next(step for step in workflow["jobs"]["contracts-and-scenarios"]["steps"]
                if step.get("name") == "Run test suite")
    assert step["run"].split() == ["python", "-m", "pytest", "-q", "tests", "model_training/tests"]
