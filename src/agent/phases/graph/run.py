"""Graph phase: common execution and evidence handling."""
from __future__ import annotations
from src.agent.core.graph_context import graph_bound
import json


class GraphPhase:
    """Phase operations using the shared run state; no independent lifecycle."""

    def _build_graph_evidence_projection(self) -> dict:
        """Project graph-tool results into authoritative, model-independent facts."""
        graph_tools = {
            "get_network_topology", "get_attack_surface", "get_attack_paths",
            "get_risk_scores", "get_device_info",
        }
        latest: dict[str, dict] = {}
        device_details: list[dict] = []
        log_path = self.run_dir / "tool_calls.jsonl"
        if log_path.exists():
            for line in log_path.read_text(encoding="utf-8").splitlines():
                try:
                    entry = json.loads(line)
                except (TypeError, ValueError, json.JSONDecodeError):
                    continue
                tool = entry.get("tool", "")
                if tool not in graph_tools:
                    continue
                raw_result = entry.get("result", "")
                try:
                    payload = json.loads(raw_result) if isinstance(raw_result, str) else raw_result
                except (TypeError, ValueError, json.JSONDecodeError):
                    payload = {"unparsed_result": str(raw_result)}
                observation = {
                    "payload": payload,
                    "evidence_ref": entry.get("evidence_ref", ""),
                    "args": entry.get("args", {}) or {},
                }
                if tool == "get_device_info":
                    device_details.append(observation)
                else:
                    latest[tool] = observation

        topology = latest.get("get_network_topology", {}).get("payload", {})
        if not isinstance(topology, dict):
            topology = {}
        nodes = topology.get("nodes", [])
        edges = topology.get("edges", [])
        nodes = nodes if isinstance(nodes, list) else []
        edges = edges if isinstance(edges, list) else []

        surface_payload = latest.get("get_attack_surface", {}).get("payload", [])
        if isinstance(surface_payload, dict):
            surface = surface_payload.get("nodes", surface_payload.get("devices", []))
        else:
            surface = surface_payload
        surface = surface if isinstance(surface, list) else []

        # Reuse the broad attack-surface observation as the primary per-device
        # ledger. A later get_device_info call only fills a device omitted by
        # that broad result (or fields that were absent); it is not required as
        # a duplicate observation for every declared node.
        surface_by_id: dict[str, dict] = {}
        surface_order: list[str] = []
        surface_device_ids: set[str] = set()
        for device in surface:
            if not isinstance(device, dict) or not device.get("id"):
                continue
            device_id = str(device["id"])
            if device_id not in surface_by_id:
                surface_order.append(device_id)
            surface_by_id[device_id] = dict(device)
            surface_device_ids.add(device_id)

        detailed_device_ids: set[str] = set()
        for observation in device_details:
            payload = observation.get("payload")
            if not isinstance(payload, dict) or not payload.get("id"):
                continue
            device_id = str(payload["id"])
            detailed_device_ids.add(device_id)
            if device_id not in surface_by_id:
                surface_order.append(device_id)
                surface_by_id[device_id] = dict(payload)
                continue
            merged = dict(payload)
            merged.update(surface_by_id[device_id])
            surface_by_id[device_id] = merged

        surface = [surface_by_id[device_id] for device_id in surface_order]
        device_coverage = {
            device_id: (
                "get_attack_surface"
                if device_id in surface_device_ids
                else "get_device_info"
            )
            for device_id in surface_order
            if device_id in surface_device_ids or device_id in detailed_device_ids
        }
        service_count = sum(
            len(device.get("services", []))
            for device in surface
            if isinstance(device, dict) and isinstance(device.get("services", []), list)
        )

        paths_payload = latest.get("get_attack_paths", {}).get("payload", {})
        if isinstance(paths_payload, list):
            attack_paths = paths_payload
            paths_note = ""
        elif isinstance(paths_payload, dict):
            candidate_paths = paths_payload.get(
                "attack_paths", paths_payload.get("paths", [])
            )
            attack_paths = candidate_paths if isinstance(candidate_paths, list) else []
            paths_note = str(paths_payload.get("note", ""))
        else:
            attack_paths = []
            paths_note = ""

        risk_payload = latest.get("get_risk_scores", {}).get("payload", {})
        if isinstance(risk_payload, list):
            risk_scores = risk_payload
            risk_note = ""
        elif isinstance(risk_payload, dict):
            candidate_scores = risk_payload.get(
                "devices", risk_payload.get("risk_scores", [])
            )
            risk_scores = candidate_scores if isinstance(candidate_scores, list) else []
            risk_note = str(risk_payload.get("note", ""))
        else:
            risk_scores = []
            risk_note = ""

        from src.agent.core.graph_context import current_graph_context

        graph_state = current_graph_context()
        discovery_subnet = ""
        if isinstance(graph_state.discovery_mode, dict):
            discovery_subnet = str(graph_state.discovery_mode.get("target_network") or "")

        projection = {
            "schema_version": "1",
            "source": "discovery_scope" if (not latest and discovery_subnet) else "tool_calls.jsonl",
            "scenario": topology.get("scenario", ""),
            "subnet": topology.get("subnet") or discovery_subnet,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "nodes": nodes,
            "edges": edges,
            "attack_surface": surface,
            "service_count": service_count,
            "attack_paths": attack_paths,
            "attack_path_count": len(attack_paths),
            "attack_paths_note": paths_note,
            "risk_scores": risk_scores,
            "risk_scores_note": risk_note,
            "device_details": device_details,
            "device_coverage": device_coverage,
            "evidence_refs": {
                tool: observation.get("evidence_ref", "")
                for tool, observation in latest.items()
            },
            "note": (
                "Deterministic graph-tool projection. Narrative conclusions in "
                "01_graph_analysis.md must not override these factual counts."
            ),
        }
        (self.run_dir / "01_graph_evidence.json").write_text(
            json.dumps(projection, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return projection


def _run_blackbox_discovery_graph(explicit) -> str:
    """Fast deterministic Phase 1 when no topology or scenario is declared.

    Avoids spending ~15 LLM turns querying empty discovery-mode graph tools
    before Phase 2 has discovered any live hosts. Grey-box runs (with an
    operator-supplied `audit_topology`) and lab scenarios keep the full LLM
    Phase 1 analysis.
    """
    graph = explicit.run_context.graph
    dm = graph.discovery_mode or {}
    target_network = str(dm.get("target_network") or explicit.variables.get("target_subnet") or "").strip()
    excluded = [str(ip) for ip in (dm.get("excluded_ips") or []) if str(ip).strip()]
    config = explicit.config
    emit = explicit.emit

    if emit:
        emit({
            "type": "phase_start",
            "phase": config.phase,
            "name": config.name,
            "description": config.description,
            "deliverable": config.deliverable_file,
        })

    if explicit.tracker:
        explicit.tracker.start_phase(config.name)

    excl_line = ", ".join(f"`{ip}`" for ip in excluded) if excluded else "none"
    content = (
        "# Phase 1: Graph Analysis — Black-Box Discovery Scope\n\n"
        "## 1. Discovery Scope\n\n"
        f"- **Mode:** Black-box live discovery (no pre-declared network topology provided).\n"
        f"- **Authorized Target Network:** `{target_network or 'unspecified'}`\n"
        f"- **Excluded Infrastructure IPs (never probed):** {excl_line}\n"
        "- **Declared Devices / Links:** 0 (deterministic fast-path — no LLM calls spent on empty topology).\n\n"
        "## 2. Reconnaissance Plan\n\n"
        "- Phase 2 active reconnaissance (`arp_scan`, `nmap_discovery`, `nmap_scan`) will enumerate live hosts,\n"
        "  open TCP/UDP services, MAC vendors, and observed L2/L3 topology links within the authorized scope.\n"
        "- Attack surface, risk prioritization, and vulnerability analysis begin once live hosts are observed.\n"
    )
    out_path = explicit.run_dir / config.deliverable_file
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(content, encoding="utf-8")

    if explicit.tracker:
        explicit.tracker.record_validation_result(success=True)
        explicit.tracker.end_phase()

    if emit:
        emit({
            "type": "phase_done",
            "phase": config.phase,
            "name": config.name,
            "status": "completed",
            "deliverable": config.deliverable_file,
            "turns": 0,
            "cost_usd": 0.0,
        })
    return "completed"


@graph_bound
def run(context, config=None, stream_callback=None):
    from src.agent.phases.context import phase_context
    explicit = phase_context(context, config, stream_callback)
    graph = explicit.run_context.graph
    if (
        graph.discovery_mode is not None
        and graph.audit_topology is None
        and graph.scenario_topology is None
    ):
        return _run_blackbox_discovery_graph(explicit)
    return explicit.services.execute(explicit.config, explicit.emit)
