from pathlib import Path
from unittest.mock import MagicMock, patch

import yaml

from src.benchmark.scenario_deployment import GeneratedScenarioDeployment
from src.benchmark.scenario_generator import ScenarioGenerator
from src.agent.pipeline import Pipeline


ROOT = Path(__file__).resolve().parents[1]


def test_exported_variant_gets_an_ansible_overlay_and_dynamic_lease(tmp_path):
    generator = ScenarioGenerator(
        ROOT,
        tmp_path / "generated",
        tmp_path / "exports",
    )
    variant = generator.generate("api-authorization", 501, "rename_hosts")
    generator.export_variant(variant["id"])

    deployment = GeneratedScenarioDeployment.prepare(
        variant["id"],
        export_store=generator.export_store,
        state_root=tmp_path / "deployments",
    )
    overlay = yaml.safe_load(deployment.overlay_path.read_text(encoding="utf-8"))
    runtime = overlay["benchmark_scenarios"][variant["id"]]

    assert deployment.base_vmid >= 700
    assert overlay["scenario_id"] == variant["id"]
    assert overlay["source_scenario_id"] == "15"
    assert overlay["benchmark_scenario_vmid_ranges"][variant["id"]] == deployment.base_vmid
    assert overlay["router_name"] == runtime["router_name"]
    assert overlay["router_name"].startswith("g")
    assert all(item["deploy_name"].startswith("g") for item in runtime["services"])
    assert {item["name"] for item in runtime["services"]} >= {"identity", "fleet-api"}
    assert all("vmid_offset" in item and "ip" in item for item in runtime["services"])

    same = GeneratedScenarioDeployment.prepare(
        variant["id"],
        export_store=generator.export_store,
        state_root=tmp_path / "deployments",
    )
    assert same.base_vmid == deployment.base_vmid

    deployment.release()
    assert not deployment.lease_path.exists()
    assert not deployment.overlay_path.exists()


def test_dynamic_leases_do_not_overlap(tmp_path):
    generator = ScenarioGenerator(
        ROOT,
        tmp_path / "generated",
        tmp_path / "exports",
    )
    first = generator.generate("api-authorization", 502, "rotate_ips")
    second = generator.generate("ota-lifecycle", 503, "rotate_ips")
    generator.export_variant(first["id"])
    generator.export_variant(second["id"])
    state_root = tmp_path / "deployments"

    left = GeneratedScenarioDeployment.prepare(
        first["id"], export_store=generator.export_store, state_root=state_root,
    )
    right = GeneratedScenarioDeployment.prepare(
        second["id"], export_store=generator.export_store, state_root=state_root,
    )

    assert left.base_vmid + left.max_vmid_offset < right.base_vmid
    left.release()
    right.release()

def test_pipeline_passes_generated_overlay_to_ansible(tmp_path, monkeypatch):
    generator = ScenarioGenerator(
        ROOT,
        tmp_path / "generated",
        tmp_path / "exports",
    )
    variant = generator.generate("ota-lifecycle", 504, "rename_hosts")
    generator.export_variant(variant["id"])
    deployment = GeneratedScenarioDeployment.prepare(
        variant["id"],
        export_store=generator.export_store,
        state_root=tmp_path / "deployments",
    )
    import src.agent.pipeline as pipeline_module

    monkeypatch.setattr(pipeline_module, "OUTPUT_DIR", tmp_path / "runs")
    provider = MagicMock(model="test-model", provider="test-provider")
    pipeline = Pipeline(provider=provider, scenario_id=variant["id"], dry_run=True)
    pipeline._generated_deployment = deployment

    completed = MagicMock(returncode=0, stdout="ok", stderr="")
    with patch("src.agent.pipeline.subprocess.run", return_value=completed) as run:
        assert pipeline._run_playbook("03_deploy_scenario.yml", None, "start", "done")

    command = run.call_args.args[0]
    assert f"@{deployment.overlay_path}" in command
    assert "source_scenario_id=17" in command
    deployment.release()
def test_legacy_export_uses_source_suffixes_with_generated_hostnames(tmp_path):
    generator = ScenarioGenerator(
        ROOT,
        tmp_path / "generated",
        tmp_path / "exports",
    )
    variant = generator.generate("scenario-1", 505, "rename_hosts")
    generator.export_variant(variant["id"])
    deployment = GeneratedScenarioDeployment.prepare(
        variant["id"],
        export_store=generator.export_store,
        state_root=tmp_path / "deployments",
    )
    overlay = yaml.safe_load(deployment.overlay_path.read_text(encoding="utf-8"))
    runtime = overlay["benchmark_scenarios"][variant["id"]]

    assert overlay["source_scenario_id"] == "1"
    assert {item["name"] for item in runtime["services"]} >= {"mqtt", "web", "ssh"}
    assert all(item["deploy_name"].startswith("g") for item in runtime["services"])
    assert runtime["router_vulns"] == ["telnet"]
    deployment.release()
