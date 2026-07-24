"""API endpoints for immutable generated scenario previews."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from src.benchmark.scenario_generator import ScenarioGenerator, ScenarioGeneratorError


router = APIRouter()
generator = ScenarioGenerator()
Operation = Literal["rotate_ips", "rename_hosts", "swap_profiles"]


class GenerateRequest(BaseModel):
    blueprint_id: str
    seed: int = Field(ge=0, le=2**31 - 1)
    operation: Operation = "rotate_ips"


class MutateRequest(BaseModel):
    seed: int = Field(ge=0, le=2**31 - 1)
    operation: Operation = "rotate_ips"


def _call(action):
    try:
        return action()
    except ScenarioGeneratorError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/blueprints")
def list_blueprints():
    return {"blueprints": generator.list_blueprints()}


@router.get("")
def list_generated_scenarios():
    return {"variants": generator.list_variants()}


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
        )
    )
