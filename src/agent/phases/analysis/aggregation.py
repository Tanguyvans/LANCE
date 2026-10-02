"""Phase 3 aggregation: capture, load, normalize, project, then write."""
from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
import json
import logging
from pathlib import Path

from src.agent.core import runtime
from src.agent.phases.analysis.aggregation_context import AggregationContext, AggregationResult
from src.agent.phases.analysis.aggregation_loading import load_inputs
from src.agent.phases.analysis.aggregation_normalization import normalize_candidates
from src.agent.phases.analysis.aggregation_projection import detect_attack_chains, project_candidates

log = logging.getLogger(__name__)


def capture_context(
    run_dir: Path, *, compact_local: bool = False,
    decision_policy: str = "llm", benchmark_split: str = "unassigned",
) -> AggregationContext:
    """Capture graph/tool state once, after device scanning and analysis."""
    from src.agent.tools import graph_tools

    nodes = []
    ip_to_device_id = {}
    try:
        surface = json.loads(runtime.get_attack_surface())
        nodes = surface.get("nodes", []) if isinstance(surface, dict) else surface
        if not isinstance(nodes, list):
            nodes = []
        # Historical remapping accepts mapping-shaped surfaces only.
        if isinstance(surface, dict):
            ip_to_device_id = {node["ip"]: node["id"] for node in nodes
                               if node.get("ip") and node.get("id")}
    except Exception as exc:
        log.debug("Attack surface snapshot unavailable: %s", exc)
    # Only public identity fields are consumed by aggregation/extract_findings.
    nodes = [
        {key: deepcopy(node[key]) for key in ("id", "ip", "role", "type") if key in node}
        if isinstance(node, dict) else deepcopy(node)
        for node in nodes
    ]
    topology = graph_tools._scenario_topology
    if topology is not None:
        topology = {
            "edges": [
                {key: deepcopy(edge[key]) for key in ("source", "target") if key in edge}
                for edge in topology.get("edges", [])
            ],
            "node_index": {
                identifier: {"ip": node.get("ip", "")}
                for identifier, node in topology["node_index"].items()
            },
        }
    return AggregationContext(
        run_dir=run_dir, compact_local=compact_local, decision_policy=decision_policy,
        benchmark_split=benchmark_split, surface_nodes=nodes,
        surface_roles={str(node.get("id") or ""): str(node.get("role") or node.get("type") or "").casefold()
                       for node in nodes if isinstance(node, dict)},
        ip_to_device_id=ip_to_device_id,
        topology=topology,
        tool_names=frozenset(runtime.available_tool_names()),
    )


def render_projection(
    context: AggregationContext, final: list[dict], raw_records: list[dict],
) -> AggregationResult:
    compact_mode = context.compact_local
    compact_observations: list[dict] = []
    severity_counts = {
        "high": 0, "medium": 0, "low": 0, "info": 0, "critical": 0,
    }
    for finding in final:
        severity = (finding.get("severity") or "").casefold()
        if severity in severity_counts:
            severity_counts[severity] += 1

    raw_projection = {
        "schema_version": "2",
        "policy": (
            "Information-preserving candidate registry. Exclusion from the "
            "canonical queue never deletes the model output."
        ),
        "candidate_count": len(raw_records),
        "canonical_count": len(final),
        "candidates": raw_records,
    }

    result = {
        "vulnerabilities": final,
        **({"configuration_observations": compact_observations} if compact_mode else {}),
        "attack_chain_hints": detect_attack_chains(final, context.topology),
        "summary": {
            "total": len(final),
            "critical": severity_counts["critical"],
            "high": severity_counts["high"],
            "medium": severity_counts["medium"],
            "low": severity_counts["low"],
            "info": severity_counts["info"],
            "raw_candidates": len(raw_records),
            "raw_projection": "03_vuln_analysis_raw.json",
        },
    }

    return AggregationResult(
        result, raw_projection,
        {"schema_version": "1", "observations": compact_observations} if compact_mode else None,
    )


def write_projection(run_dir: Path, result: AggregationResult) -> tuple[Path, ...]:
    """Write the existing fixed phase-3 artifacts, including on phase-2.5 refresh."""
    artifacts = [("03_vuln_analysis_raw.json", result.raw)]
    if result.configuration_observations is not None:
        artifacts.append(("03_config_observations.json", result.configuration_observations))
    artifacts.append(("03_vuln_analysis.json", result.canonical))
    paths = []
    for filename, payload in artifacts:
        path = run_dir / filename
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        paths.append(path)
    return tuple(paths)


def aggregate(context: AggregationContext) -> AggregationResult:
    inputs = load_inputs(context)
    eligible = normalize_candidates(context, inputs)
    final = project_candidates(
        eligible, inputs.records, mqtt_observations=inputs.mqtt_observations,
        previous_ids=inputs.previous_ids,
    )
    result = render_projection(context, final, inputs.records)
    write_projection(context.run_dir, result)
    print(f"  Aggregated {len(inputs.records)} raw candidates → {len(final)} canonical "
          "findings → 03_vuln_analysis.json")
    log.info("Information-preserving aggregation: %d candidates → %d canonical → %s",
             len(inputs.records), len(final), context.run_dir / "03_vuln_analysis.json")
    return result


class FindingAggregation:
    """Phase-2.5 adapter; the aggregation stages receive explicit inputs."""
    def _aggregate_device_vulns(
        self, config: runtime.AgentConfig,
        stream_callback: Callable[[dict], None] | None = None,
    ) -> None:
        aggregate(capture_context(
            self.run_dir, compact_local=self._uses_compact_local_moe(),
            decision_policy=self.decision_policy, benchmark_split=self.benchmark_split,
        ))
