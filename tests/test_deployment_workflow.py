"""Guard deployment ordering and exercise the real update commands locally."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest
import yaml


WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"


def _workflow(name):
    # Preserve GitHub's "on" key instead of interpreting it as a YAML 1.1 bool.
    return yaml.load((WORKFLOWS / name).read_text(), Loader=yaml.BaseLoader)


def test_deployment_requires_successful_checks_and_cannot_run_directly():
    ci = _workflow("benchmark-integrity.yml")
    deploy = _workflow("update-master.yml")
    job = ci["jobs"]["deploy-master"]

    assert set(job["needs"]) == {"contracts-and-scenarios", "sealed-worker-image"}
    assert job["if"] == (
        "github.ref == 'refs/heads/main' && github.event_name != 'pull_request' "
        "&& needs.contracts-and-scenarios.outputs.full == 'true'"
    )
    assert job["uses"] == "./.github/workflows/update-master.yml"
    assert "workflow_dispatch" in ci["on"]
    assert set(deploy["on"]) == {"workflow_call"}
    assert deploy["concurrency"] == {
        "group": "deploy-nato-master",
        "cancel-in-progress": "false",
    }
    step = deploy["jobs"]["update"]["steps"][1]
    assert step["env"]["DEPLOY_SHA"] == "${{ github.sha }}"
    assert deploy["jobs"]["update"]["runs-on"] == ["self-hosted", "nato-master"]
    development = ci["jobs"]["deploy-development"]
    assert development["needs"] == job["needs"]
    assert "github.event_name != 'pull_request'" in development["if"]
    assert "needs.contracts-and-scenarios.outputs.full == 'true'" in development["if"]
    assert ci["on"]["push"]["branches"] == ["main", "dev/1", "dev/2"]
    for script in (WORKFLOWS.parents[1] / "scripts/deployment").glob("*.sh"):
        subprocess.run(["bash", "-n", str(script)], check=True)


@pytest.mark.parametrize("state", ["behind", "current", "ahead", "dirty", "diverged"])
def test_update_uses_tested_commit_and_preserves_local_work(tmp_path, monkeypatch, state):
    # Never use the developer's Git hooks, signing setup, or actual remote.
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")

    def git(repo, *args):
        return subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "-C", str(repo), *args],
            text=True, capture_output=True, check=True,
        ).stdout.strip()

    def commit(repo, content):
        (repo / "app.txt").write_text(content)
        git(repo, "add", "app.txt")
        git(repo, "-c", "user.name=Deployment test", "-c", "user.email=test@example.invalid",
            "commit", "-qm", content)
        return git(repo, "rev-parse", "HEAD")

    remote = tmp_path / "remote"
    remote.mkdir()
    git(remote, "init", "-q", "-b", "main")
    before = commit(remote, "before")
    tested = commit(remote, "tested")
    latest = commit(remote, "not tested yet")
    checkout = tmp_path / "checkout"
    git(tmp_path, "clone", "-q", str(remote), str(checkout))
    start = {"current": tested, "ahead": latest}.get(state, before)
    git(checkout, "switch", "-qc", "deployed", start)
    if state == "dirty":
        (checkout / "app.txt").write_text("local work")
    elif state == "diverged":
        start = commit(checkout, "local commit")
    local_config = checkout / "inventory.local.yml"
    local_config.write_text("keep local configuration")

    script = WORKFLOWS.parents[1] / "scripts/deployment/update-checkout.sh"
    result = subprocess.run(
        ["bash", str(script), "main", tested],
        cwd=checkout,
        env={**os.environ, "DEPLOY_SHA": tested, "DEPLOY_REMOTE": str(remote)},
        text=True, capture_output=True,
    )

    succeeds = state in {"behind", "current"}
    assert (result.returncode == 0) == succeeds, result.stdout + result.stderr
    assert git(checkout, "rev-parse", "HEAD") == (tested if succeeds else start)
    assert local_config.read_text() == "keep local configuration"
    if succeeds:
        assert (checkout / "app.txt").read_text() == "tested"
    elif state == "dirty":
        assert (checkout / "app.txt").read_text() == "local work"


def test_development_checkout_can_switch_branches_without_touching_data(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    def git(root, *args):
        return subprocess.check_output(["git", "-c", "core.hooksPath=/dev/null", "-C", str(root), *args], text=True).strip()
    remote = tmp_path / "remote"
    remote.mkdir()
    git(remote, "init", "-q", "-b", "main")
    (remote / "app").write_text("main")
    git(remote, "add", "app")
    git(remote, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "main")
    main = git(remote, "rev-parse", "HEAD")
    git(remote, "switch", "-qc", "dev/1")
    (remote / "app").write_text("dev")
    git(remote, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qam", "dev")
    dev = git(remote, "rev-parse", "HEAD")
    checkout = tmp_path / "checkout"
    git(tmp_path, "clone", "-q", str(remote), str(checkout))
    (checkout / "data").mkdir()
    (checkout / "data/lance.db").write_text("private data")
    script = WORKFLOWS.parents[1] / "scripts/deployment/update-checkout.sh"
    for sha in (main, dev):
        subprocess.run(["bash", str(script), "dev-1", sha], cwd=checkout,
                       env={**os.environ, "DEPLOY_REMOTE": str(remote)}, check=True, capture_output=True)
        assert git(checkout, "rev-parse", "HEAD") == sha
        assert (checkout / "data/lance.db").read_text() == "private data"
