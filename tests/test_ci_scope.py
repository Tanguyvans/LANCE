"""CI skips known documents only, using complete event ranges in real Git repos."""
from importlib.util import module_from_spec, spec_from_file_location
import os
from pathlib import Path
import subprocess

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github/scripts/ci_scope.py"
spec = spec_from_file_location("ci_scope", SCRIPT)
scope = module_from_spec(spec)
spec.loader.exec_module(scope)


@pytest.mark.parametrize("path", [
    "README.md", "AGENTS.md", "tests/README.md", "src/agent/phases/README.md",
    "docs/architecture/run-artifacts.md", "docs/images/example.svg",
    "research/study/report.tex", "research/study/report.pdf", "research/study/sources.bib",
])
def test_known_documents_use_lightweight_checks(path):
    assert scope.documentation_only([path])


def test_known_empty_diff_requires_no_runtime_checks():
    assert scope.documentation_only([])


@pytest.mark.parametrize("path", [
    "src/agent/prompts/analyze_device.md", "src/agent/templates/06_report.md",
    "src/agent/skills/example/SKILL.md", "research/study/experiment.py",
    "research/study/config.yaml", "docs/example.py", "src/agent/pipeline.py",
    "model_training/train.py", "tests/test_example.py", "requirements.txt",
    "benchmarks/scenarios/s1.yaml", "Dockerfile", ".dockerignore",
    ".github/workflows/docker.yml", ".github/scripts/ci_scope.py", "unknown-file",
])
def test_code_configuration_and_unknown_paths_keep_complete_checks(path):
    assert not scope.documentation_only(["docs/guide.md", path])


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    root = tmp_path / "repo"
    root.mkdir()

    def git(*args):
        return subprocess.check_output(
            ["git", "-c", "core.hooksPath=/dev/null", "-C", str(root), *args], text=True,
        ).strip()

    git("init", "-q", "-b", "main")

    def commit(path, content):
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        git("add", "--all")
        git("-c", "user.name=CI test", "-c", "user.email=ci@example.invalid", "commit", "-qm", "test")
        return git("rev-parse", "HEAD")

    return root, git, commit


def test_multi_commit_push_includes_code_before_last_documentation_commit(repo):
    root, _, commit = repo
    base = commit("src/app.py", "before\n")
    commit("src/app.py", "changed\n")
    commit("docs/guide.md", "first document\n")
    commit("docs/guide.md", "last document\n")
    assert scope.classify("push", {"before": base}, "refs/heads/main", cwd=root) == (True, base)


@pytest.mark.parametrize("operation", ["rename", "delete"])
def test_removed_code_cannot_be_hidden_by_documentation_paths(repo, operation):
    root, git, commit = repo
    base = commit("src/app.py", "before\n")
    if operation == "rename":
        (root / "research").mkdir()
        git("mv", "src/app.py", "research/app.md")
    else:
        git("rm", "src/app.py")
    commit("docs/guide.md", "documentation\n")
    assert "src/app.py" in scope.changed_paths(base, cwd=root)
    assert scope.classify("push", {"before": base}, "refs/heads/main", cwd=root) == (True, base)


@pytest.mark.parametrize("event_name", ["push", "pull_request"])
def test_documentation_range_uses_lightweight_path_and_keeps_base(repo, event_name):
    root, _, commit = repo
    base = commit("src/app.py", "before\n")
    commit("docs/guide.md", "documentation\n")
    event = {"before": base} if event_name == "push" else {"pull_request": {"base": {"sha": base}}}
    assert scope.classify(event_name, event, "refs/heads/main", cwd=root) == (False, base)


def test_pull_request_merge_commit_includes_runtime_change(repo):
    root, git, commit = repo
    commit("src/app.py", "base\n")
    git("switch", "-qc", "feature")
    commit("src/app.py", "feature\n")
    git("switch", "main")
    base = commit("docs/guide.md", "base advanced\n")
    git("-c", "user.name=CI test", "-c", "user.email=ci@example.invalid",
        "merge", "--no-ff", "feature", "-m", "merge")
    event = {"pull_request": {"base": {"sha": base}}}
    assert scope.classify("pull_request", event, "refs/pull/1/merge", cwd=root) == (True, base)


@pytest.mark.parametrize("event_name,event,ref", [
    ("push", {"before": "0" * 40}, "refs/heads/main"),
    ("push", {}, "refs/heads/main"),
    ("push", {"before": "untrusted ref"}, "refs/heads/main"),
    ("pull_request", {}, "refs/pull/1/merge"),
    ("workflow_dispatch", {}, "refs/heads/main"),
    ("push", {"before": "a" * 40}, "refs/tags/v1"),
])
def test_manual_release_and_unknown_ranges_always_run_full(event_name, event, ref):
    assert scope.classify(event_name, event, ref) == (True, "")


def test_missing_base_fetch_failure_falls_back_to_full(repo):
    root, _, commit = repo
    commit("README.md", "documentation\n")
    assert scope.classify("push", {"before": "a" * 40}, "refs/heads/main", cwd=root) == (True, "")


def test_shallow_checkout_fetches_authoritative_base_of_multi_commit_push(repo, tmp_path):
    root, _, commit = repo
    base = commit("README.md", "base\n")
    commit("src/app.py", "code\n")
    commit("docs/guide.md", "first\n")
    commit("docs/guide.md", "last\n")
    checkout = tmp_path / "shallow"
    subprocess.run(["git", "clone", "-q", "--depth=2", root.as_uri(), str(checkout)], check=True)
    assert scope.classify("push", {"before": base}, "refs/heads/main", cwd=checkout) == (True, base)


def test_script_metadata_failure_emits_full_output(tmp_path):
    event = tmp_path / "event.json"
    event.write_text("invalid JSON")
    output = tmp_path / "output"
    subprocess.run(["python3", str(SCRIPT)], check=True, env={
        **os.environ, "GITHUB_EVENT_PATH": str(event), "GITHUB_OUTPUT": str(output),
        "GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/main",
    }, capture_output=True)
    assert output.read_text() == "full=true\nbase=\n"


def workflow(name):
    return yaml.load((ROOT / ".github/workflows" / name).read_text(), Loader=yaml.BaseLoader)


@pytest.mark.parametrize("name", ["benchmark-integrity.yml", "docker.yml"])
def test_workflow_remains_present_and_cancels_only_superseded_pull_requests(name):
    config = workflow(name)
    for event in ["push", "pull_request"]:
        assert "paths" not in config["on"][event]
        assert "paths-ignore" not in config["on"][event]
    assert config["concurrency"]["cancel-in-progress"] == "${{ github.event_name == 'pull_request' }}"
    assert "github.event.pull_request.number || github.run_id" in config["concurrency"]["group"]
    for job in config["jobs"].values():
        if "steps" in job:
            detect = next(step for step in job["steps"] if step.get("id") == "scope")
            assert "if" not in detect
            assert detect["run"] == "python3 .github/scripts/ci_scope.py"


def test_full_code_checks_and_worker_oracle_guard_remain_enforced():
    config = workflow("benchmark-integrity.yml")
    steps = {step["name"]: step for step in config["jobs"]["contracts-and-scenarios"]["steps"]}
    tests = steps["Run test suite"]
    assert tests["run"] == "python -m pytest -q tests model_training/tests"
    for name in ["Run test suite", "Validate generated ground truths", "Validate benchmark deployment syntax"]:
        assert steps[name]["if"] == "steps.scope.outputs.full == 'true'"
    assert "if" not in steps["Reject whitespace errors"]
    assert 'git diff --check "$SCOPE_BASE" HEAD' in steps["Reject whitespace errors"]["run"]
    worker = config["jobs"]["sealed-worker-image"]["steps"]
    build = next(step for step in worker if step["name"] == "Build isolated worker")
    assert build["with"]["load"] == "true"
    assert "scope=sealed-worker" in build["with"]["cache-from"]
    guard = next(step for step in worker if step["name"] == "Assert oracle files are absent")
    assert worker.index(build) < worker.index(guard)
    assert guard["if"] == build["if"] == "steps.scope.outputs.full == 'true'"
    assert "ground_truth*" in guard["run"]
    for name in ["deploy-master", "deploy-development"]:
        deploy = config["jobs"][name]
        assert set(deploy["needs"]) == {"contracts-and-scenarios", "sealed-worker-image"}
        assert "always()" not in deploy["if"]
        assert "outputs.full == 'true'" in deploy["if"]
