"""API endpoints for immutable generated scenario previews."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from src.benchmark.scenario_exports import ScenarioExportError
from src.benchmark.scenario_deployment import GeneratedScenarioDeployment
from src.benchmark.scenario_alterations import alteration_catalog
from src.benchmark.scenario_builder import ScenarioBuilder, ScenarioBuilderError
from src.benchmark.scenario_generator import ScenarioGenerator, ScenarioGeneratorError


router = APIRouter()
generator = ScenarioGenerator()
builder = ScenarioBuilder()

class GenerateRequest(BaseModel):
    blueprint_id: str
    seed: int = Field(ge=0, le=2**31 - 1)
    operation: str = "rotate_ips"


class MutateRequest(BaseModel):
    seed: int = Field(ge=0, le=2**31 - 1)
    operation: str = "rotate_ips"
    parameters: dict[str, Any] = Field(default_factory=dict)


class ComposeRequest(BaseModel):
    """Manual Scenario Lab input; official benchmark files remain untouched."""

    scenario: dict[str, Any]


class BuilderFindingRequest(BaseModel):
    node_id: str = Field(min_length=1, max_length=64)
    candidate_id: str = Field(min_length=1, max_length=160)


class BuilderComposeRequest(BaseModel):
    topology_id: str = Field(min_length=1, max_length=64)
    selected_nodes: list[str] = Field(default_factory=list, max_length=64)
    findings: list[BuilderFindingRequest] = Field(default_factory=list, max_length=128)
    name: str = Field(default="", max_length=120)
    description: str = Field(default="", max_length=500)
    seed: int = Field(default=0, ge=0, le=2**31 - 1)
    execution_profile: str = Field(default="auto", max_length=32)


class BuilderRandomRequest(BaseModel):
    topology_id: str | None = Field(default=None, max_length=64)
    seed: int = Field(default=0, ge=0, le=2**31 - 1)
    min_nodes: int = Field(default=2, ge=1, le=32)
    max_nodes: int = Field(default=5, ge=1, le=32)
    min_vulnerabilities: int = Field(default=2, ge=1, le=128)
    max_vulnerabilities: int = Field(default=6, ge=1, le=128)
    execution_profile: str = Field(default="auto", max_length=32)

def _call(action):
    try:
        return action()
    except (ScenarioGeneratorError, ScenarioExportError, ScenarioBuilderError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/blueprints")
def list_blueprints():
    return {"blueprints": generator.list_blueprints()}


@router.get("")
def list_generated_scenarios():
    return {"variants": generator.list_variants()}


@router.get("/alterations")
def list_alterations():
    return {"catalog_version": 1, "alterations": alteration_catalog()}


@router.post("/compose", status_code=201)
def compose_manual_scenario(request: ComposeRequest):
    return _call(lambda: generator.compose_custom(request.scenario))


@router.get("/builder/topologies")
def list_builder_topologies():
    return _call(lambda: {"topologies": builder.list_topologies()})


@router.get("/builder/catalog/{topology_id}")
def get_builder_catalog(topology_id: str):
    return _call(lambda: builder.catalog(topology_id))


@router.post("/builder/compose", status_code=201)
def compose_builder_scenario(request: BuilderComposeRequest):
    def action():
        spec, selection = builder.build_spec(
            topology_id=request.topology_id,
            selected_nodes=request.selected_nodes,
            findings=[item.dict() for item in request.findings],
            name=request.name or None,
            description=request.description or None,
            seed=request.seed,
            execution_profile=request.execution_profile,
        )
        result = generator.compose_custom(spec)
        result["builder"] = selection
        return result

    return _call(action)


@router.post("/builder/random", status_code=201)
def compose_random_builder_scenario(request: BuilderRandomRequest):
    def action():
        spec, selection = builder.random_spec(
            topology_id=request.topology_id,
            seed=request.seed,
            min_nodes=request.min_nodes,
            max_nodes=request.max_nodes,
            min_vulnerabilities=request.min_vulnerabilities,
            max_vulnerabilities=request.max_vulnerabilities,
            execution_profile=request.execution_profile,
        )
        result = generator.compose_custom(spec)
        result["builder"] = selection
        return result

    return _call(action)


@router.post("", status_code=201)
def generate_scenario(request: GenerateRequest):
    return _call(
        lambda: generator.generate(
            request.blueprint_id,
            request.seed,
            request.operation,
        )
    )


@router.get("/{variant_id}")
def get_generated_scenario(variant_id: str):
    return _call(lambda: generator.get_variant(variant_id))


@router.delete("/{variant_id}")
def delete_generated_scenario(variant_id: str):
    from src.api.routes import pipeline

    if GeneratedScenarioDeployment.from_lease(variant_id) is not None:
        raise HTTPException(
            status_code=409,
            detail="Cannot delete a generated scenario while its Proxmox deployment is active",
        )
    if pipeline._state.get("running") and pipeline._state.get("scenario_id") == variant_id:
        raise HTTPException(
            status_code=409,
            detail="Cannot delete a generated scenario while its dashboard run is active",
        )
    deleted = _call(lambda: generator.delete_variant(variant_id))
    return {"deleted": True, "scenario": deleted}


@router.get("/{variant_id}/topology")
def get_generated_topology(variant_id: str):
    return _call(lambda: generator.get_topology_graph(variant_id))


@router.post("/{variant_id}/mutations", status_code=201)
def mutate_generated_scenario(variant_id: str, request: MutateRequest):
    return _call(
        lambda: generator.mutate(
            variant_id,
            request.seed,
            request.operation,
            request.parameters,
        )
    )

@router.post("/{variant_id}/export", status_code=201)
def export_generated_scenario(variant_id: str):
    return _call(lambda: generator.export_variant(variant_id))


@router.delete("/{variant_id}/export")
def delete_exported_scenario(variant_id: str):
    from src.api.routes import pipeline

    if GeneratedScenarioDeployment.from_lease(variant_id) is not None:
        raise HTTPException(
            status_code=409,
            detail="Cannot delete an exported scenario while its Proxmox deployment is active",
        )
    if pipeline._state.get("running") and pipeline._state.get("scenario_id") == variant_id:
        raise HTTPException(
            status_code=409,
            detail="Cannot delete an exported scenario while its dashboard run is active",
        )
    deleted = _call(lambda: generator.delete_export(variant_id))
    return {"deleted": True, "scenario": deleted}
