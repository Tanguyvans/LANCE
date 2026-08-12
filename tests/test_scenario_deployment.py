import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

import yaml

from src.benchmark.scenario_deployment import GeneratedScenarioDeployment, ManualScenarioDeployment
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


def test_manual_profiles_allocate_distinct_runtime_overlays(tmp_path):
    from src.benchmark.scenario_spec import load_scenario_spec

    generator = ScenarioGenerator(ROOT, tmp_path / "generated", tmp_path / "exports")
    flat = generator.compose_custom(load_scenario_spec(ROOT / "benchmarks/scenarios_manual/flat_logical_chain.yaml"))
    multihop = generator.compose_custom(load_scenario_spec(ROOT / "benchmarks/scenarios_manual/true_multihop_reference.yaml"))
    state_root = tmp_path / "deployments"

    left = ManualScenarioDeployment.prepare(
        flat["id"], generated_root=generator.storage_root, state_root=state_root,
    )
    right = ManualScenarioDeployment.prepare(
        multihop["id"], generated_root=generator.storage_root, state_root=state_root,
    )
    flat_overlay = yaml.safe_load(left.overlay_path.read_text(encoding="utf-8"))
    multi_overlay = yaml.safe_load(right.overlay_path.read_text(encoding="utf-8"))

    assert left.source_scenario_id == "14"
    assert left.execution_profile == "flat_roles"
    assert right.source_scenario_id == "20"
    assert right.execution_profile == "true_multihop"
    assert flat_overlay["manual_scenario"] is True
    assert flat_overlay["manual_expected_control_count"] == 0
    assert multi_overlay["manual_expected_control_count"] == 3
    assert left.base_vmid + left.max_vmid_offset < right.base_vmid

    left.release()
    right.release()


def test_manual_execution_rejects_an_unknown_runtime_role():
    from src.benchmark.scenario_composer import ScenarioComposer
    from src.benchmark.scenario_spec import ScenarioSpecError, load_scenario_spec

    spec = load_scenario_spec(ROOT / "benchmarks/scenarios_manual/flat_logical_chain.yaml")
    spec["attack_paths"] = []
    spec["topology"] = {
        "ref": "flat",
        "overrides": {
            "services": [{
                "name_template": "s{sid}-unknown",
                "vmid_offset": 1,
                "ip": "192.168.100.11",
                "role": "unknown_role",
            }],
        },
    }
    with pytest.raises(ScenarioSpecError, match="No execution provider"):
        ScenarioComposer(ROOT).compose(spec)


def test_pipeline_passes_manual_overlay_and_provider_profile_to_ansible(tmp_path, monkeypatch):
    from src.benchmark.scenario_spec import load_scenario_spec

    generator = ScenarioGenerator(ROOT, tmp_path / "generated", tmp_path / "exports")
    variant = generator.compose_custom(load_scenario_spec(ROOT / "benchmarks/scenarios_manual/flat_logical_chain.yaml"))
    deployment = ManualScenarioDeployment.prepare(
        variant["id"], generated_root=generator.storage_root, state_root=tmp_path / "deployments",
    )
    import src.agent.pipeline as pipeline_module

    monkeypatch.setattr(pipeline_module, "OUTPUT_DIR", tmp_path / "runs")
    provider = MagicMock(model="test-model", provider="test-provider")
    pipeline = Pipeline(provider=provider, scenario_id=variant["id"], dry_run=True)
    pipeline._generated_deployment = deployment

    completed = MagicMock(returncode=0, stdout="ok", stderr="")
    with patch("src.agent.pipeline.subprocess.run", return_value=completed) as run:
        assert pipeline._run_playbook("04_inject_vulns.yml", None, "start", "done")

    command = run.call_args.args[0]
    assert f"@{deployment.overlay_path}" in command
    assert "source_scenario_id=14" in command
    deployment.release()


def test_exported_manual_bundle_prepares_from_export_store(tmp_path):
    from src.benchmark.scenario_spec import load_scenario_spec

    generator = ScenarioGenerator(ROOT, tmp_path / "generated", tmp_path / "exports")
    variant = generator.compose_custom(
        load_scenario_spec(ROOT / "benchmarks/scenarios_manual/flat_logical_chain.yaml")
    )
    generator.export_variant(variant["id"])

    deployment = ManualScenarioDeployment.prepare(
        variant["id"],
        export_store=generator.export_store,
        state_root=tmp_path / "deployments",
    )
    overlay = yaml.safe_load(deployment.overlay_path.read_text(encoding="utf-8"))

    assert deployment.execution_profile == "flat_roles"
    assert overlay["manual_scenario"] is True
    assert overlay["benchmark_scenarios"][variant["id"]]["services"]
    deployment.release()


def test_pipeline_selects_manual_adapter_for_exported_builder_bundle(tmp_path, monkeypatch):
    from src.benchmark.scenario_spec import load_scenario_spec
    import src.agent.pipeline as pipeline_module

    generator = ScenarioGenerator(ROOT, tmp_path / "generated", tmp_path / "exports")
    variant = generator.compose_custom(
        load_scenario_spec(ROOT / "benchmarks/scenarios_manual/flat_logical_chain.yaml")
    )
    generator.export_variant(variant["id"])

    monkeypatch.setattr(pipeline_module, "default_export_store", lambda: generator.export_store)
    provider = MagicMock(model="test-model", provider="test-provider")
    pipeline = Pipeline(provider=provider, scenario_id=variant["id"], dry_run=True)
    monkeypatch.setattr(pipeline, "_teardown_all_running_scenarios", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(pipeline, "_run_playbook", lambda *_args, **_kwargs: True)

    assert pipeline._run_scenario_deploy() is True
    assert isinstance(pipeline._generated_deployment, ManualScenarioDeployment)
    assert pipeline._generated_deployment.execution_profile == "flat_roles"
    pipeline._generated_deployment.release()
