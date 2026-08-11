from pathlib import Path

import pytest

from src.benchmark.scenario_builder import ScenarioBuilder, ScenarioBuilderError
from src.benchmark.scenario_generator import ScenarioGenerator


ROOT = Path(__file__).resolve().parents[1]


def _builder() -> ScenarioBuilder:
    return ScenarioBuilder(ROOT)


def test_catalog_filters_findings_by_topology_node_compatibility():
    catalog = _builder().catalog("flat")
    assert len(catalog["nodes"]) == 4
    assert all("_template" not in candidate for node in catalog["nodes"] for candidate in node["candidates"])

    web = next(node for node in catalog["nodes"] if node["role"] == "web_server")
    mqtt = next(node for node in catalog["nodes"] if node["role"] == "mqtt_broker")
    assert web["candidate_count"] > 0
    assert mqtt["candidate_count"] > 0
    assert all(candidate["role"] == "web_server" for candidate in web["candidates"])
    assert all("http" in candidate["services"] or not candidate["services"] for candidate in web["candidates"])


def test_manual_builder_materializes_only_selected_nodes_and_findings(tmp_path: Path):
    builder = _builder()
    catalog = builder.catalog("flat")
    web = next(node for node in catalog["nodes"] if node["role"] == "web_server")
    candidate = web["candidates"][0]
    spec, selection = builder.build_spec(
        topology_id="flat",
        selected_nodes=["service-2"],
        findings=[{"node_id": "service-2", "candidate_id": candidate["candidate_id"]}],
        execution_profile="preview",
        seed=7,
    )

    assert selection["selected_nodes"] == ["service-2"]
    assert len(spec["extra_vulnerabilities"]) == 1
    assert spec["extra_vulnerabilities"][0]["device"].startswith("sbuilder-flat-7-")

    generator = ScenarioGenerator(ROOT, tmp_path / "generated", tmp_path / "exports")
    result = generator.compose_custom(spec)
    variant = generator.get_variant(result["id"])
    assert result["vulnerability_count"] == 1
    assert variant["topology"]["service_count"] == 1
    assert variant["ground_truth"]["vulnerabilities"][0]["device"].endswith("-web")


def test_builder_rejects_findings_for_unselected_or_incompatible_nodes():
    builder = _builder()
    catalog = builder.catalog("flat")
    web = next(node for node in catalog["nodes"] if node["role"] == "web_server")
    candidate = web["candidates"][0]

    with pytest.raises(ScenarioBuilderError, match="not selected"):
        builder.build_spec(
            topology_id="flat",
            selected_nodes=["service-1"],
            findings=[{"node_id": "service-2", "candidate_id": candidate["candidate_id"]}],
        )

    with pytest.raises(ScenarioBuilderError, match="not compatible"):
        builder.build_spec(
            topology_id="flat",
            selected_nodes=["service-1"],
            findings=[{"node_id": "service-1", "candidate_id": candidate["candidate_id"]}],
        )


def test_random_builder_is_seeded_and_keeps_findings_on_selected_nodes():
    builder = _builder()
    first, first_selection = builder.random_spec(
        topology_id="flat",
        seed=19,
        min_nodes=2,
        max_nodes=3,
        min_vulnerabilities=2,
        max_vulnerabilities=4,
    )
    second, second_selection = builder.random_spec(
        topology_id="flat",
        seed=19,
        min_nodes=2,
        max_nodes=3,
        min_vulnerabilities=2,
        max_vulnerabilities=4,
    )

    assert first_selection == second_selection
    assert first == second
    selected = set(first_selection["selected_nodes"])
    assert selected
    assert first_selection["findings"]
    assert {item["node_id"] for item in first_selection["findings"]} <= selected
    assert len(first_selection["findings"]) <= 4

def test_builder_reports_missing_catalog_sources(tmp_path: Path):
    builder = ScenarioBuilder(tmp_path)

    with pytest.raises(ScenarioBuilderError, match="catalogue unavailable"):
        builder.list_topologies()
