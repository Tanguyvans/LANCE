"""Inputs captured once at the aggregation boundary and its explicit outputs."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class AggregationContext:
    run_dir: Path
    compact_local: bool = False
    decision_policy: str = "llm"
    benchmark_split: str = "unassigned"
    surface_nodes: list[dict] = field(default_factory=list)
    surface_roles: dict[str, str] = field(default_factory=dict)
    ip_to_device_id: dict[str, str] = field(default_factory=dict)
    topology: dict | None = None
    tool_names: frozenset[str] = frozenset()


@dataclass
class AggregationInputs:
    findings: list[dict]
    records: list[dict]
    cve_evidence: dict[tuple[str, str], dict]
    mqtt_observations: list[dict]
    previous_ids: dict[tuple, str]


@dataclass(frozen=True)
class AggregationResult:
    canonical: dict
    raw: dict
    configuration_observations: dict | None = None
