"""API endpoints for immutable generated scenario previews."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from src.benchmark.scenario_exports import ScenarioExportError
from src.benchmark.scenario_deployment import GeneratedScenarioDeployment
from src.benchmark.scenario_alterations import alteration_catalog
from src.benchmark.scenario_generator import ScenarioGenerator, ScenarioGeneratorError


router = APIRouter()
generator = ScenarioGenerator()
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


def _call(action):
    try:
        return action()
    except (ScenarioGeneratorError, ScenarioExportError) as exc:
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
