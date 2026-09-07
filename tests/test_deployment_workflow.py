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
    assert job["if"] == "github.ref == 'refs/heads/main' && github.event_name != 'pull_request'"
    assert job["uses"] == "./.github/workflows/update-master.yml"
    assert "workflow_dispatch" in ci["on"]
    assert set(deploy["on"]) == {"workflow_call"}
    assert deploy["concurrency"] == {
        "group": "deploy-nato-master",
        "cancel-in-progress": "false",
    }
    step = deploy["jobs"]["update"]["steps"][0]
    assert step["env"]["DEPLOY_SHA"] == "${{ github.sha }}"
    assert step["working-directory"] == "/opt/nato-smartcity-iot"
    assert step["shell"] == "bash"
    subprocess.run(["bash", "-n"], input=step["run"], text=True, check=True)


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

    step = _workflow("update-master.yml")["jobs"]["update"]["steps"][0]
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", step["run"]],
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
