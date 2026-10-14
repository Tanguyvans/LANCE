"""Exercise pilot deployment plans and evidence bundles without a laboratory."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tarfile

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("pilot_support", ROOT / "scripts/benchmark/pilot_support.py")
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)


@pytest.mark.parametrize("sid,base,count", [("1", 100, 3), ("14", 300, 10), ("15", 320, 6), ("1h", 100, 3)])
def test_deployment_overlay_matches_ground_truth(sid, base, count):
    plan = support.deployment_overlay(ROOT, sid)
    scenario = plan["benchmark_scenarios"][sid]
    truth = yaml.safe_load((ROOT / f"benchmarks/ground_truth/dev/scenario_{sid}.yaml").read_text())
    assert plan["benchmark_scenario_vmid_ranges"][sid] == base
    assert len(scenario["services"]) == count
    assert plan["router_name"] == truth["topology"]["router"]["name"]
    assert {(f"s{sid}-{s['name']}", s["ip"], base + s["vmid_offset"]) for s in scenario["services"]} == {
        (s["name"], s["ip"], s["vmid"]) for s in truth["topology"]["services"]
    }


def test_s1h_activates_existing_hardening_and_negative_checks():
    plan = support.deployment_overlay(ROOT, "1h")
    scenario = plan["benchmark_scenarios"]["1h"]
    assert plan["pilot_topology_source_scenario_id"] == "1"
    assert plan["source_scenario_id"] == "14"
    assert scenario["router_vulns"] == []
    assert all(s["security_profile"] == "hardened" for s in scenario["services"])
    assert support.deployment_overlay(ROOT, "1")["benchmark_scenarios"]["1"]["router_vulns"] == ["telnet"]


@pytest.mark.parametrize("sid", ["1", "14", "15", "1h"])
def test_overlay_keeps_other_scenarios_visible_to_conflict_checks(sid):
    plan = support.deployment_overlay(ROOT, sid)
    assert plan["benchmark_scenario_vmid_ranges"]["1"] == 100
    assert plan["benchmark_scenario_vmid_ranges"]["14"] == 300
    assert plan["benchmark_scenario_vmid_ranges"]["15"] == 320
    assert plan["benchmark_scenarios"]["1"]["router_vulns"] == ["telnet"]
    assert set(plan["benchmark_scenario_vmid_ranges"]) <= set(plan["benchmark_scenarios"])


def _attempt(tmp_path):
    trial = tmp_path / "trial"
    runs = tmp_path / "agent"
    trial.mkdir()
    runs.mkdir()
    (trial / ".marker-rules").touch()
    os.utime(trial / ".marker-rules", ns=(1, 1))
    (trial / "deploy1.log").write_text("deployment proof\n")
    run = runs / "2026-10-14_142612"
    run.mkdir()
    return trial, runs, run


def test_capture_filters_other_trials_and_refuses_ambiguity(tmp_path):
    trial, runs, run = _attempt(tmp_path)
    (run / "run_meta.json").write_text(json.dumps({"decision_policy": "rules", "experiment": {"trial_id": "s14-r1"}}))
    other = runs / "2026-10-14_142613"
    other.mkdir()
    (other / "run_meta.json").write_text(json.dumps({"decision_policy": "llm", "experiment": {"trial_id": "s14-r1"}}))
    (runs / ".benchmark-score-cache").mkdir()
    assert support.capture_run(trial, runs, "rules", "s14-r1") == run
    (other / "run_meta.json").write_text((run / "run_meta.json").read_text())
    with pytest.raises(ValueError, match="Ambiguous"):
        support.capture_run(trial, runs, "rules", "s14-r1")


def test_bundle_preserves_incomplete_run_all_proofs_and_hidden_files(tmp_path):
    trial, runs, run = _attempt(tmp_path)
    # The run was killed before its metadata was written.
    contents = {"tool_calls.jsonl": b'{"proof":"raw"}\n', "03_scans/web.json": b"{}", "04_exploitation.json": b"{}", ".receipt": b"hidden"}
    for filename, data in contents.items():
        p = run / filename
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    archive = support.archive_trial(trial, runs, tmp_path / "evidence", "s14-r1")
    manifest = json.loads((archive.parent / "evidence-manifest.json").read_text())
    assert manifest["runs"] == {"rules": f"runs/{run.name}", "llm": None}
    assert manifest["archive_sha256"] == hashlib.sha256(archive.read_bytes()).hexdigest()
    with tarfile.open(archive) as bundle:
        for name, expected in manifest["files"].items():
            data = bundle.extractfile(name).read()
            assert expected == {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        for filename, data in contents.items():
            assert bundle.extractfile(f"runs/{run.name}/{filename}").read() == data
    summary = tmp_path / "summary"
    support.export_summary(archive, summary, runs)
    assert not list(summary.rglob("tool_calls.jsonl"))
    assert not list(summary.rglob("*.tar.gz"))


def test_failed_preparation_archives_without_fabricating_a_run(tmp_path):
    trial = tmp_path / "trial"
    trial.mkdir()
    (trial / "deploy1.log").write_text("failed")
    archive = support.archive_trial(trial, tmp_path / "absent-run-store", tmp_path / "evidence", "s1h-r1")
    manifest = json.loads((archive.parent / "evidence-manifest.json").read_text())
    assert manifest["runs"] == {"rules": None, "llm": None}
    assert "trial/deploy1.log" in manifest["files"]


def test_summary_exports_only_current_pair_metadata_and_comparison(tmp_path):
    trial, runs, first = _attempt(tmp_path)
    second = runs / "2026-10-14_142613"
    second.mkdir()
    for policy, run in (("rules", first), ("llm", second)):
        (trial / f"{policy}_dir.txt").write_text(str(run))
        for name in ("run_meta.json", "audit_inventory.json", "cost_summary.json"):
            (run / name).write_text('{}\n')
        (run / "tool_calls.jsonl").write_text('raw response retained only locally\n')
    (trial / "comparison-s14-r1.json").write_text('{"comparable":true}\n')
    archive = support.archive_trial(trial, runs, tmp_path / "evidence", "s14-r1")
    summary = tmp_path / "summary"
    support.export_summary(archive, summary, runs)
    assert {p.relative_to(summary).as_posix() for p in summary.rglob("*") if p.is_file()} == {
        "evidence-manifest.json", "comparison-s14-r1.json",
        *(f"runs/{run.name}/{name}" for run in (first, second)
          for name in ("run_meta.json", "audit_inventory.json", "cost_summary.json")),
    }


@pytest.mark.parametrize("failed_playbook", ["99_teardown.yml", "03_deploy_scenario.yml", "04_inject_vulns.yml", "05_populate_services.yml", "06_verify.yml"])
def test_deployment_stops_at_first_failed_playbook(tmp_path, failed_playbook):
    workflow = yaml.load((ROOT / ".github/workflows/pilot-campaign.yml").read_text(), Loader=yaml.BaseLoader)
    script = next(s["run"] for s in workflow["jobs"]["trial"]["steps"] if s.get("id") == "trial")
    function = "deploy_arm() {" + script.split("deploy_arm() {", 1)[1].split("run_arm() {", 1)[0]
    fake = tmp_path / "ansible"
    fake.write_text('#!/bin/bash\nname=${1##*/}\nprintf "%s\\n" "$name" >> "$CALL_LOG"\n[ "$name" != "$FAIL_PLAYBOOK" ] || exit 7\n')
    fake.chmod(0o755)
    log = tmp_path / "calls"
    result = subprocess.run(["bash", "-c", 'set -euo pipefail\nDEPLOY_ID=14\nOWNED=false\nPLAYBOOK=("$FAKE")\n' + function + '\ndeploy_arm || exit $?'],
                            env={**os.environ, "FAKE": str(fake), "CALL_LOG": str(log), "FAIL_PLAYBOOK": failed_playbook}, capture_output=True, text=True)
    assert result.returncode == 7, result.stderr
    sequence = ["99_teardown.yml", "03_deploy_scenario.yml", "04_inject_vulns.yml", "05_populate_services.yml", "06_verify.yml"]
    assert log.read_text().splitlines() == sequence[:sequence.index(failed_playbook) + 1]


@pytest.mark.parametrize("unsafe", ["symlink", "outside"])
def test_archive_refuses_evidence_outside_the_run(unsafe, tmp_path):
    trial, runs, run = _attempt(tmp_path)
    outside = tmp_path / "other"
    outside.mkdir()
    (outside / "secret").write_text("must not archive")
    if unsafe == "symlink":
        (run / "escape").symlink_to(outside, target_is_directory=True)
    else:
        (trial / "rules_dir.txt").write_text(str(outside))
    with pytest.raises(ValueError, match="symlink|outside"):
        support.archive_trial(trial, runs, tmp_path / "evidence", "s14-r1")


def test_workflow_uses_dispatch_preserves_lock_and_archives_after_failures(tmp_path):
    workflow = yaml.load((ROOT / ".github/workflows/pilot-campaign.yml").read_text(), Loader=yaml.BaseLoader)
    assert set(workflow["on"]) == {"workflow_dispatch"}
    assert workflow["concurrency"]["cancel-in-progress"] == "false"
    steps = workflow["jobs"]["trial"]["steps"]
    for index, step in enumerate(steps):
        if "run" in step:
            script = tmp_path / f"step-{index}.sh"
            script.write_text(step["run"])
            subprocess.run(["bash", "-n", str(script)], check=True)
    archive = next(s for s in steps if s["name"] == "Archive complete evidence on nato")
    assert archive["if"].startswith("always()")
    assert "/opt/nato-smartcity-iot/output/pilot-evidence/" in archive["run"]
    upload = next(s for s in steps if s.get("uses") == "actions/upload-artifact@v4")
    assert "pilot-summary-" in upload["with"]["path"]
    assert "pilot-evidence" not in upload["with"]["path"]


def test_audit_resource_freeze_is_unchanged():
    from src.agent.audit_experiment import resource_manifest
    frozen = json.loads((ROOT / "benchmarks/experiments/policy-comparison/pilot-2026-10.json").read_text())
    assert resource_manifest() == frozen["configuration"]["resource_manifest_sha256"]
