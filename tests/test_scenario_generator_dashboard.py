from pathlib import Path

from src.benchmark.scenario_generator import ScenarioGenerator
from src.benchmark.scenario_spec import load_scenario_spec


ROOT = Path(__file__).resolve().parents[1]
MANUAL = ROOT / "benchmarks" / "scenarios_manual"


def test_v2_dashboard_exposes_generated_scenario_workshop():
    html = (ROOT / "src" / "static_v2" / "index.html").read_text(encoding="utf-8")

    for element_id in (
        "btnGenerator",
        "generatorModal",
        "generatorBlueprint",
        "generatorOperation",
        "btnGenerateScenario",
        "btnMutateScenario",
        "btnPreviewScenario",
    ):
        assert f'id="{element_id}"' in html
    assert '<script src="/static_v2/generator.js"></script>' in html
    assert '<script src="/static/cytoscape.min.js"></script>' in html


def test_dashboard_controller_can_export_generated_variants_for_a_run():
    javascript = (ROOT / "src" / "static_v2" / "generator.js").read_text(
        encoding="utf-8"
    )

    assert "/api/scenario-generator/blueprints" in javascript
    assert "/mutations" in javascript
    assert "/export" in javascript
    assert "state.scenario = variantId" in javascript
    assert "Generated previews are not deployable" not in javascript


def test_classic_dashboard_integrates_scenario_lab_as_native_view():
    html = (ROOT / "src" / "static" / "index.html").read_text(encoding="utf-8")

    assert 'data-view="scenario-lab"' in html
    assert 'id="sl-section-nav"' in html
    assert 'id="sl-tab-variants"' in html
    assert 'id="sl-tab-builder"' in html
    for element_id in (
        "sl-builder-topology",
        "sl-builder-name",
        "sl-builder-compose",
        "sl-builder-random",
        "sl-builder-nodes",
        "sl-builder-candidates",
        "sl-builder-selection",
    ):
        assert f'id="{element_id}"' in html
    assert '<option value="auto">Déployable si compatible</option>' in html
    assert '<option value="preview">Prévisualisation uniquement</option>' in html
    assert 'id="scenario-lab-view"' in html
    assert 'id="sl-blueprint"' in html
    assert 'id="sl-operation"' in html
    assert 'id="sl-generate"' in html
    assert 'id="sl-mutate"' in html
    assert 'id="sl-export"' in html
    assert 'id="sl-delete-export"' in html
    assert 'id="sl-delete-variant"' in html
    assert 'id="btn-delete-exported-scenario"' in html
    assert 'id="sl-cy"' in html
    assert 'data-sl-section="variants"' in html
    assert 'data-sl-section="builder"' in html
    assert '<script src="/static/scenario_generator.js"></script>' in html
    assert 'href="/v2#scenario-lab"' not in html


def test_classic_dashboard_controller_connects_generator_api_and_preview_graph():
    javascript = (ROOT / "src" / "static" / "scenario_generator.js").read_text(
        encoding="utf-8"
    )
    app = (ROOT / "src" / "static" / "app.js").read_text(encoding="utf-8")
    assert "/builder/topologies" in javascript
    assert "/builder/catalog/" in javascript
    assert "/builder/random" in javascript

    assert "/api/scenario-generator/blueprints" in javascript
    assert "/mutations" in javascript
    assert "/export" in javascript
    assert "method: 'DELETE'" in javascript
    assert "_deleteScenarioLabVariant" in javascript
    assert "deleteSelectedExportedScenario" in app
    assert "/topology" in javascript
    assert "cytoscape({" in javascript
    assert "_setScenarioLabSection" in javascript
    assert "deployment_status" in javascript
    assert "scenario-lab-view" in app
    assert "if (isScenarioLab && typeof openScenarioLab" in app


def test_classic_dashboard_keeps_exported_builder_scenarios_as_benchmark_options():
    source = (ROOT / "src" / "api" / "routes" / "scenarios.py").read_text(encoding="utf-8")

    assert 'if variant["id"] in scenarios_by_id' in source
    assert '"kind": "scenario-lab-export"' in source


def test_base_dashboard_lists_one_exported_builder_scenario(tmp_path, monkeypatch):
    from src.api.routes import scenarios

    generator = ScenarioGenerator(ROOT, tmp_path / "generated", tmp_path / "exports")
    variant = generator.compose_custom(load_scenario_spec(MANUAL / "flat_logical_chain.yaml"))
    generator.export_variant(variant["id"])
    monkeypatch.setattr(scenarios, "generated_scenarios", generator)
    monkeypatch.setattr(scenarios, "default_export_store", lambda: generator.export_store)

    payload = scenarios.list_scenarios()
    matches = [item for item in payload["scenarios"] if item["id"] == variant["id"]]

    assert len(matches) == 1
    assert matches[0]["exported"] is True
    assert matches[0]["kind"] == "scenario-lab-export"
    assert matches[0]["deployment_supported"] is True

def test_docker_image_keeps_canonical_scenario_lab_assets():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")

    assert "COPY benchmarks/topologies/ ./benchmarks/topologies/" in dockerfile
    assert "COPY benchmarks/packs/definitions/ ./benchmarks/packs/definitions/" in dockerfile
    assert "static_docker" not in dockerfile
    assert "benchmarks/" in dockerignore
    assert "!benchmarks/topologies/**" in dockerignore
    assert "!benchmarks/packs/definitions/**" in dockerignore
