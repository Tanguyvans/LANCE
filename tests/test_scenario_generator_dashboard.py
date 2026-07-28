from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


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


def test_dashboard_controller_keeps_generated_variants_preview_only():
    javascript = (ROOT / "src" / "static_v2" / "generator.js").read_text(
        encoding="utf-8"
    )

    assert "/api/scenario-generator/blueprints" in javascript
    assert "/mutations" in javascript
    assert "state.generatedVariant" in javascript
    assert "event.stopImmediatePropagation()" in javascript
    assert "Generated previews are not deployable" in javascript


def test_classic_dashboard_integrates_scenario_lab_as_native_view():
    html = (ROOT / "src" / "static" / "index.html").read_text(encoding="utf-8")

    assert 'data-view="scenario-lab"' in html
    assert 'id="scenario-lab-view"' in html
    assert 'id="sl-blueprint"' in html
    assert 'id="sl-operation"' in html
    assert 'id="sl-generate"' in html
    assert 'id="sl-mutate"' in html
    assert 'id="sl-export"' in html
    assert 'id="sl-delete-export"' in html
    assert 'id="btn-delete-exported-scenario"' in html
    assert 'id="sl-cy"' in html
    assert '<script src="/static/scenario_generator.js"></script>' in html
    assert 'href="/v2#scenario-lab"' not in html


def test_classic_dashboard_controller_connects_generator_api_and_preview_graph():
    javascript = (ROOT / "src" / "static" / "scenario_generator.js").read_text(
        encoding="utf-8"
    )
    app = (ROOT / "src" / "static" / "app.js").read_text(encoding="utf-8")

    assert "/api/scenario-generator/blueprints" in javascript
    assert "/mutations" in javascript
    assert "/export" in javascript
    assert "method: 'DELETE'" in javascript
    assert "deleteSelectedExportedScenario" in app
    assert "/topology" in javascript
    assert "cytoscape({" in javascript
    assert "deployment_status" in javascript
    assert "scenario-lab-view" in app
    assert "if (isScenarioLab && typeof openScenarioLab" in app
